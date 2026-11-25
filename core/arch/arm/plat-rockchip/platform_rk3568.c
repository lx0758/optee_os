// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, OrangePi-3B AOSP project contributors
 *
 * RK3566/RK3568 platform support for OP-TEE: DDR firewall + hardware TRNG.
 *
 * 参数与寄存器来源见 openspec/changes/orangepi-3b-optee-bringup/design.md 与
 * vendor/6xyun/bootloader/README.md：
 *  - 防火墙布局复刻 TF-A plat/rockchip/rk3568/drivers/secure/secure.{h,c}
 *    （区域单位 128 KiB，使能位在 0x80）；
 *  - TRNG 是 cryptov2 的 RNG 块，寄存器语义取自 RK 内核
 *    drivers/char/hw_random/rockchip-rng.c 的 crypto_v2_read()；
 *  - 软件 PRNG 用同一 TRNG 取种，避免落到时间戳弱种子。
 */

#include <crypto/crypto.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <rng_support.h>
#include <stdbool.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <util.h>

/* ---- DDR firewall (RK3568: 128 KiB granules, CON at 0x80) ---- */
#define FIREWALL_DDR_RGN(i)		((i) * 0x4)
#define FIREWALL_DDR_RGN_CNT		16
#define FIREWALL_DDR_CON		0x80
#define FIREWALL_GRAN_SHIFT		17	/* 128 KiB */
#define FW_MAX_ADDR			BIT64(32)	/* 4 GiB */

/* 15-bit base/top fields, in 128 KiB units. */
#define RG_MAP_SECURE(top, base) \
	(((((top) - 1) & 0x7fff) << 16) | ((base) & 0x7fff))

/* ---- cryptov2 RNG block (secure alias at TRNG_S_BASE) ---- */
#define TRNG_RNG_BASE_OFFS		0x400
#define TRNG_RNG_CTL			0x000
#define TRNG_RNG_SAMPLE_CNT		0x004
#define TRNG_RNG_DOUT_0			0x010

#define TRNG_RNG_LEN_256		(3 << 4)
#define TRNG_RNG_SLOWER_RING0		(1 << 2)
#define TRNG_RNG_ENABLE			(1 << 1)
#define TRNG_RNG_START			(1 << 0)

#define TRNG_SAMPLE_CNT			100
#define TRNG_BLOCK_BYTES		32
#define TRNG_POLL_TIMEOUT		100000

/* 厂商 BL32 在 TRNG 初始化时写 SGRF：置位 0x0c 的 bit6/7，清除 0x250 的 bit1。 */
#define SGRF_TRNG_CLK_CON		0x0c
#define SGRF_TRNG_RST_CON		0x250
#define SGRF_TRNG_CLK_BITS		(BIT(7) | BIT(6))
#define SGRF_TRNG_RST_BIT		BIT(1)

/*
 * CFG_WITH_SOFTWARE_PRNG 默认是 y；若不覆盖 plat_init_soft_prng()，OP-TEE 会
 * 用时间戳播种（CFG_INSECURE 下的弱实现）。这里用硬件 TRNG 取 48 字节作为种子。
 */
#define TRNG_ENTROPY_256		48

/* ---- OTP read-only (RK3568 SBPI/user interface) ---- */
#define OTP_WRITE_MASK			16
#define OTP_SECURE_WORDS		448	/* 0x000-0x1bf words are secure */

#define OTP_REG_SBPI_CTRL		0x0020
#define OTP_REG_SBPI_CMD_VALID_PRE	0x0024
#define OTP_REG_SBPI_CS_VALID_PRE	0x0028
#define OTP_REG_USER_CTRL		0x0100
#define OTP_REG_USER_QP			0x0120
#define OTP_REG_SBPI_CMD_OFFSET(n)	(0x1000 + ((n) << 2))
#define OTP_REG_SBPI_READ_DATA_BASE	0x2000
#define OTP_REG_INT_STATUS		0x0304

#define OTP_SBPI_DEV_ID_SHIFT		8
#define OTP_SBPI_CS_AUTO		(1 << 2)
#define OTP_SBPI_ENABLE			(1 << 0)
#define OTP_SBPI_VALID_CMD(n)		(0xffff0000 | (n))
#define OTP_USER_DCTRL			(1 << 0)
#define OTP_INT_DONE			(1 << 1)

#define CRU_CLKGATES_CON(i)		(0x300 + ((i) * 4))
#define CRU_SOFTRSTS_CON(n)		(0x300 + ((n) * 4))
#define SCRU_GATE_CON01			0x0184
#define SGRF_SOC_CON2			0x0008

#define CLK_S_OTP_USER_EN		(1 << 7)
#define CLK_S_OTP_SBPI_EN		(1 << 6)
#define PCLK_S_OTP_EN			(1 << 5)
#define PCLK_PHY_OTP_EN			(1 << 13)
#define OTP_PHY_SRSTN			(1u << 15)
#define SGRF_CON_OTP_CKE		(1 << 2)
#define SGRF_CON_OTP_SECURE		(1 << 1)

/* HUK from the vendor device-key slot at OTP byte offset 0x40. */
#define RK3568_HUK_OTP_BYTE_ADDR	0x40
#define RK3568_HUK_OTP_BYTES		32

struct otp_clocks {
	uint32_t cru_gate26;
	uint32_t cru_gate34;
	uint32_t scru_gate01;
};

register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DDR_BASE,
			FIREWALL_DDR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TRNG_S_BASE, TRNG_S_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SGRF_BASE, SGRF_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, OTP_S_BASE, OTP_S_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CRU_BASE, CRU_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SCRU_BASE, SCRU_SIZE);

static bool trng_clk_ready;

static void trng_clk_enable(void)
{
	vaddr_t sgrf = 0;

	if (trng_clk_ready)
		return;

	sgrf = (vaddr_t)phys_to_virt_io(SGRF_BASE, SGRF_SIZE);
	if (!sgrf)
		return;

	/* 打开安全侧 CRYPTO/TRNG 时钟，并释放复位。 */
	io_write32(sgrf + SGRF_TRNG_CLK_CON,
		   (SGRF_TRNG_CLK_BITS << 16) | SGRF_TRNG_CLK_BITS);
	io_write32(sgrf + SGRF_TRNG_RST_CON, SGRF_TRNG_RST_BIT << 16);

	trng_clk_ready = true;
}

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw = 0;
	paddr_t ed = 0;

	if (rgn < 0 || rgn >= FIREWALL_DDR_RGN_CNT || !sz)
		return -1;

	ed = st + sz;
	if (ed < st || ed > FW_MAX_ADDR ||
	    (st & (BIT(FIREWALL_GRAN_SHIFT) - 1)) ||
	    (ed & (BIT(FIREWALL_GRAN_SHIFT) - 1))) {
		EMSG("Invalid TZDRAM range: 0x%lx-0x%lx", st, ed);
		return -1;
	}

	fw = (vaddr_t)phys_to_virt_io(FIREWALL_DDR_BASE, FIREWALL_DDR_SIZE);
	if (!fw)
		return -1;

	io_write32(fw + FIREWALL_DDR_RGN(rgn),
		   RG_MAP_SECURE(ed >> FIREWALL_GRAN_SHIFT,
				 st >> FIREWALL_GRAN_SHIFT));
	io_setbits32(fw + FIREWALL_DDR_CON, BIT(rgn));

	MSG("TZDRAM 0x%lx-0x%lx protected by DDR firewall region %d",
	    st, ed, rgn);

	return 0;
}

static TEE_Result trng_read_block(uint8_t out[TRNG_BLOCK_BYTES])
{
	vaddr_t base = (vaddr_t)phys_to_virt_io(TRNG_S_BASE, TRNG_S_SIZE);
	uint32_t ctl = TRNG_RNG_LEN_256 | TRNG_RNG_SLOWER_RING0 |
		       TRNG_RNG_ENABLE | TRNG_RNG_START;
	size_t i = 0;

	if (!base)
		return TEE_ERROR_GENERIC;

	io_write32(base + TRNG_RNG_BASE_OFFS + TRNG_RNG_SAMPLE_CNT,
		   TRNG_SAMPLE_CNT);
	/* Rockchip convention: value in the low 16 bits, write mask in the high 16 bits. */
	io_write32(base + TRNG_RNG_BASE_OFFS + TRNG_RNG_CTL,
		   ctl | (UINT32_C(0xffff) << 16));

	for (i = 0; i < TRNG_POLL_TIMEOUT; i++) {
		if (!(io_read32(base + TRNG_RNG_BASE_OFFS + TRNG_RNG_CTL) &
		      TRNG_RNG_START))
			break;
	}

	if (i == TRNG_POLL_TIMEOUT) {
		io_write32(base + TRNG_RNG_BASE_OFFS + TRNG_RNG_CTL,
			   UINT32_C(0xffff) << 16);
		EMSG("TRNG timeout");
		return TEE_ERROR_BUSY;
	}

	/* Registers hold big-endian words. */
	for (i = 0; i < TRNG_BLOCK_BYTES; i += 4) {
		uint32_t v = io_read32(base + TRNG_RNG_BASE_OFFS +
				       TRNG_RNG_DOUT_0 + i);

		out[i + 0] = v >> 24;
		out[i + 1] = v >> 16;
		out[i + 2] = v >> 8;
		out[i + 3] = v;
	}

	/* Close/disable the RNG block. */
	io_write32(base + TRNG_RNG_BASE_OFFS + TRNG_RNG_CTL,
		   UINT32_C(0xffff) << 16);

	return TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	static struct mutex trng_mutex = MUTEX_INITIALIZER;
	uint8_t *p = buf;
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&trng_mutex);
	trng_clk_enable();

	while (len) {
		uint8_t block[TRNG_BLOCK_BYTES] = { 0 };
		size_t n = MIN(len, sizeof(block));

		res = trng_read_block(block);
		if (res)
			break;

		memcpy(p, block, n);
		p += n;
		len -= n;
	}

	mutex_unlock(&trng_mutex);

	return res;
}

#ifdef CFG_WITH_SOFTWARE_PRNG
void plat_init_soft_prng(void)
{
	uint8_t seed[TRNG_ENTROPY_256] = { };
	TEE_Result res = TEE_SUCCESS;

	res = hw_get_random_bytes(seed, sizeof(seed));
	if (res != TEE_SUCCESS)
		panic("Failed to get TRNG seed data");

	res = crypto_rng_init(seed, sizeof(seed));
	if (res != TEE_SUCCESS)
		panic("Failed to initialize RNG with seed");
}
#endif /* CFG_WITH_SOFTWARE_PRNG */

/* ---- OTP read-only path for HUK ---- */

static int otp_wait_done(vaddr_t base)
{
	size_t timeout = 10000;	/* at most ~10 ms */

	while (timeout--) {
		if (io_read32(base + OTP_REG_INT_STATUS) & OTP_INT_DONE) {
			io_write32(base + OTP_REG_INT_STATUS, 0xffff0002);
			return 0;
		}
		udelay(1);
	}

	EMSG("OTP: SBPI done interrupt timeout");
	return -1;
}

static int otp_clocks_enable(struct otp_clocks *clk)
{
	vaddr_t cru = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);
	vaddr_t scru = (vaddr_t)phys_to_virt_io(SCRU_BASE, SCRU_SIZE);
	uint32_t v = 0;

	if (!cru || !scru)
		return -1;

	clk->cru_gate26 = io_read32(cru + CRU_CLKGATES_CON(26));
	v = clk->cru_gate26;
	if (v & CLK_S_OTP_USER_EN)
		io_write32(cru + CRU_CLKGATES_CON(26),
			   CLK_S_OTP_USER_EN << OTP_WRITE_MASK);
	if (v & CLK_S_OTP_SBPI_EN)
		io_write32(cru + CRU_CLKGATES_CON(26),
			   CLK_S_OTP_SBPI_EN << OTP_WRITE_MASK);
	if (v & PCLK_S_OTP_EN)
		io_write32(cru + CRU_CLKGATES_CON(26),
			   PCLK_S_OTP_EN << OTP_WRITE_MASK);

	clk->cru_gate34 = io_read32(cru + CRU_CLKGATES_CON(34));
	if (clk->cru_gate34 & PCLK_PHY_OTP_EN)
		io_write32(cru + CRU_CLKGATES_CON(34),
			   PCLK_PHY_OTP_EN << OTP_WRITE_MASK);

	clk->scru_gate01 = io_read32(scru + SCRU_GATE_CON01);
	if (clk->scru_gate01 & CLK_S_OTP_USER_EN)
		io_write32(scru + SCRU_GATE_CON01,
			   CLK_S_OTP_USER_EN << OTP_WRITE_MASK);
	if (clk->scru_gate01 & CLK_S_OTP_SBPI_EN)
		io_write32(scru + SCRU_GATE_CON01,
			   CLK_S_OTP_SBPI_EN << OTP_WRITE_MASK);
	if (clk->scru_gate01 & PCLK_S_OTP_EN)
		io_write32(scru + SCRU_GATE_CON01,
			   PCLK_S_OTP_EN << OTP_WRITE_MASK);

	return 0;
}

static void otp_clocks_restore(const struct otp_clocks *clk)
{
	vaddr_t cru = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);
	vaddr_t scru = (vaddr_t)phys_to_virt_io(SCRU_BASE, SCRU_SIZE);

	io_write32(cru + CRU_CLKGATES_CON(26),
		   (0xffffu << OTP_WRITE_MASK) | (clk->cru_gate26 & 0xffff));
	io_write32(cru + CRU_CLKGATES_CON(34),
		   (0xffffu << OTP_WRITE_MASK) | (clk->cru_gate34 & 0xffff));
	io_write32(scru + SCRU_GATE_CON01,
		   (0xffffu << OTP_WRITE_MASK) | (clk->scru_gate01 & 0xffff));
}

static int otp_ecc_enable(vaddr_t base)
{
	io_write32(base + OTP_REG_SBPI_CTRL,
		   (0x2 << OTP_SBPI_DEV_ID_SHIFT) |
		   (0xffu << (OTP_SBPI_DEV_ID_SHIFT + OTP_WRITE_MASK)));
	io_write32(base + OTP_REG_SBPI_CMD_VALID_PRE, OTP_SBPI_VALID_CMD(1));
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(0), 0xfa);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(1), 0x00);
	io_write32(base + OTP_REG_SBPI_CTRL,
		   (OTP_SBPI_ENABLE << OTP_WRITE_MASK) | OTP_SBPI_ENABLE);

	return otp_wait_done(base);
}

static int otp_read_halfword(uint32_t word_addr, uint16_t *out)
{
	vaddr_t base = (vaddr_t)phys_to_virt_io(OTP_S_BASE, OTP_S_SIZE);
	vaddr_t cru = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);
	vaddr_t sgrf = (vaddr_t)phys_to_virt_io(SGRF_BASE, SGRF_SIZE);
	uint32_t qp = 0;
	uint32_t lo = 0;
	uint32_t hi = 0;

	if (!base || !cru || !sgrf) {
		EMSG("OTP: register mapping unavailable");
		return -1;
	}

	/* OTP PHY reset pulse */
	io_write32(cru + CRU_SOFTRSTS_CON(28),
		   (OTP_PHY_SRSTN << OTP_WRITE_MASK) | OTP_PHY_SRSTN);
	udelay(2);
	io_write32(cru + CRU_SOFTRSTS_CON(28), OTP_PHY_SRSTN << OTP_WRITE_MASK);
	udelay(1);

	io_write32(sgrf + SGRF_SOC_CON2,
		   (SGRF_CON_OTP_CKE << OTP_WRITE_MASK) | SGRF_CON_OTP_CKE);
	udelay(2);
	io_write32(base + OTP_REG_USER_CTRL, OTP_USER_DCTRL << OTP_WRITE_MASK);
	udelay(2);

	if (otp_ecc_enable(base))
		return -1;

	io_write32(base + OTP_REG_SBPI_CTRL,
		   (OTP_SBPI_CS_AUTO << OTP_WRITE_MASK) | OTP_SBPI_CS_AUTO);
	io_write32(base + OTP_REG_SBPI_CS_VALID_PRE, 0xffff0000);
	io_write32(base + OTP_REG_SBPI_CTRL,
		   (0x2 << OTP_SBPI_DEV_ID_SHIFT) |
		   (0xffu << (OTP_SBPI_DEV_ID_SHIFT + OTP_WRITE_MASK)));
	io_write32(base + OTP_REG_SBPI_CMD_VALID_PRE, OTP_SBPI_VALID_CMD(2));
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(0), 0xfc);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(1), word_addr & 0xff);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(2), (word_addr >> 8) & 0xff);
	io_write32(base + OTP_REG_SBPI_CTRL,
		   (OTP_SBPI_ENABLE << OTP_WRITE_MASK) | OTP_SBPI_ENABLE);
	if (otp_wait_done(base))
		return -1;

	io_write32(base + OTP_REG_SBPI_CMD_VALID_PRE, OTP_SBPI_VALID_CMD(7));
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(0), 0x00);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(1), 0x00);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(2), 0x40);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(3), 0x40);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(4), 0x00);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(5), 0x02);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(6), 0x80);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(7), 0x81);
	io_write32(base + OTP_REG_SBPI_CTRL,
		   (OTP_SBPI_ENABLE << OTP_WRITE_MASK) | OTP_SBPI_ENABLE);
	if (otp_wait_done(base))
		return -1;

	qp = io_read32(base + OTP_REG_USER_QP);
	if ((qp & 0xc0) == 0xc0 || (qp & 0x20)) {
		EMSG("OTP: ECC failure at word 0x%x (qp 0x%x)", word_addr, qp);
		return -1;
	}

	lo = io_read32(base + OTP_REG_SBPI_READ_DATA_BASE + 0x20);
	hi = io_read32(base + OTP_REG_SBPI_READ_DATA_BASE + 0x24);
	*out = (uint16_t)lo;
	*out += (uint16_t)(hi << 8);

	io_write32(base + OTP_REG_SBPI_CMD_VALID_PRE, OTP_SBPI_VALID_CMD(1));
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(0), 0xa0);
	io_write32(base + OTP_REG_SBPI_CMD_OFFSET(1), 0x0);
	io_write32(base + OTP_REG_SBPI_CTRL,
		   (OTP_SBPI_ENABLE << OTP_WRITE_MASK) | OTP_SBPI_ENABLE);
	if (otp_wait_done(base))
		return -1;

	io_write32(base + OTP_REG_INT_STATUS, 0xffff0003);

	return 0;
}

/*
 * 只读：从安全 OTP 读取 byte_addr 起的 len 字节。
 * 仅支持安全区（< 0x1c0 words），不包含任何写/编程寄存器路径。
 */
static TEE_Result rk3568_otp_read(uint32_t byte_addr, uint8_t *buf, size_t len)
{
	struct otp_clocks clk = { };
	vaddr_t sgrf = 0;
	uint32_t sgrf_orig = 0;
	uint32_t word_addr = 0;
	size_t i = 0;
	int ret = -1;

	if (!buf || !len || (byte_addr & 1) || (len & 1))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((byte_addr + len) > (OTP_SECURE_WORDS * 2))
		return TEE_ERROR_BAD_PARAMETERS;

	word_addr = byte_addr / 2;

	if (otp_clocks_enable(&clk))
		return TEE_ERROR_GENERIC;

	sgrf = (vaddr_t)phys_to_virt_io(SGRF_BASE, SGRF_SIZE);
	if (!sgrf) {
		otp_clocks_restore(&clk);
		return TEE_ERROR_GENERIC;
	}
	sgrf_orig = io_read32(sgrf + SGRF_SOC_CON2);
	io_write32(sgrf + SGRF_SOC_CON2,
		   (SGRF_CON_OTP_SECURE << OTP_WRITE_MASK) |
		   SGRF_CON_OTP_SECURE);

	for (i = 0; i < len / 2; i++) {
		uint16_t v = 0;

		ret = otp_read_halfword(word_addr + i, &v);
		if (ret)
			break;

		buf[2 * i] = v & 0xff;
		buf[2 * i + 1] = v >> 8;
	}

	io_write32(sgrf + SGRF_SOC_CON2,
		   (0xffffu << OTP_WRITE_MASK) | (sgrf_orig & 0xffff));
	otp_clocks_restore(&clk);

	if (ret)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static struct mutex huk_mutex = MUTEX_INITIALIZER;
static bool huk_ready;
static struct tee_hw_unique_key huk;

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	uint8_t key[RK3568_HUK_OTP_BYTES] = { };
	bool key_is_zero = true;
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&huk_mutex);

	if (!huk_ready) {
		res = rk3568_otp_read(RK3568_HUK_OTP_BYTE_ADDR, key, sizeof(key));
		for (i = 0; i < sizeof(key); i++) {
			if (key[i]) {
				key_is_zero = false;
				break;
			}
		}

		if (res == TEE_SUCCESS && !key_is_zero) {
			memcpy(huk.data, key, HW_UNIQUE_KEY_LENGTH);
			IMSG("HUK source: OTP device key");
		} else {
			if (res != TEE_SUCCESS)
				EMSG("HUK: OTP read failed, using zero HUK");
			else
				IMSG("HUK: OTP device key is empty, using zero HUK");
			memset(&huk.data[0], 0, sizeof(huk.data));
		}

		memzero_explicit(key, sizeof(key));
		huk_ready = true;
	}

	memcpy(hwkey->data, huk.data, HW_UNIQUE_KEY_LENGTH);

	mutex_unlock(&huk_mutex);

	return TEE_SUCCESS;
}

/*
 * 在正常世界启动前完成 OTP 读取，避免运行时反复切换 OTP secure 位；
 * 之后的调用直接使用缓存。
 */
static TEE_Result huk_early_init(void)
{
	struct tee_hw_unique_key key = { };

	return tee_otp_get_hw_unique_key(&key);
}
service_init(huk_early_init);