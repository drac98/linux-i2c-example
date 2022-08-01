/*
 * Simple I2C example
 *
 * Copyright 2017 Joel Stanley <joel@jms.id.au>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>

#include <linux/types.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static inline __s32 i2c_smbus_access(int file, char read_write, __u8 command,
                                     int size, union i2c_smbus_data *data)
{
	struct i2c_smbus_ioctl_data args;

	args.read_write = read_write;
	args.command = command;
	args.size = size;
	args.data = data;
	return ioctl(file,I2C_SMBUS,&args);
}


static inline __s32 i2c_smbus_read_byte_data(int file, __u8 command)
{
	union i2c_smbus_data data;
	if (i2c_smbus_access(file,I2C_SMBUS_READ,command,
	                     I2C_SMBUS_BYTE_DATA,&data))
		return -1;
	else
		return 0x0FF & data.byte;
}

static inline __s32 i2c_smbus_write_byte_data(int file, __u8 command, __u8 value)
{
	union i2c_smbus_data data;
	data.byte = value;
	return i2c_smbus_access(file, I2C_SMBUS_WRITE, command,
				I2C_SMBUS_BYTE_DATA, &data);
}

#define REG_THR 0x00
#define REG_LCR 0x03

// Special Register Set
// Accessible only when LCR[7] is logic 1.
#define REG_DLL 0x00
#define REG_DLH 0x01

#define CLOLK_FREQUENCY 14745600
#define BAUD 			115200
#define PRESCALER 		1			//  The default value of prescaler after reset is 1.

int write_byte(int file, uint8_t reg, uint8_t val){
	int len;
	len = i2c_smbus_write_byte_data(file, reg, val);
	if (len < 0)
		err(errno, "Tried to write data '0x%02x'", val);
	return len;
}

// uint8_t read_byte(int file, uint8_t reg){
// 	uint8_t data;
// 	data = i2c_smbus_read_byte_data(file, REG_DLH);
// 	printf("Address 0x%02x: 0x%02x\n",
// 			reg, data);
// 	return data
// }

/**
 * @brief Initialize baud rate to 115200 and 8-N-1 by default
 *
 * @return true if success
 */
void init_sc16is750(uint8_t addr, int file){
	// int rc, len;
	// uint8_t lcr, dlh, dll, data, val;
	// uint16_t divisor = (CLOLK_FREQUENCY) / (BAUD * 16);	// = 8
	// dll = divisor & 0xFF;
	// dlh = divisor >> 8;

	// if (file < 0)
	// 	err(errno, "Tried to open '%s'", path);

	// lcr = i2c_smbus_read_byte_data(file, REG_LCR);
	// val = lcr || 0b10000000;

	// printf("%s: device 0x%02x at address 0x%02x: 0x%02x\n",
	// 		path, addr, reg, data);

	write_byte(file, REG_LCR, 0b10000011); 	// no parity, 1 stop bit, 8 bit word length, enable special register set
	write_byte(file, REG_DLL, 0x08);
	write_byte(file, REG_DLH, 0x00);
	write_byte(file, REG_LCR, 0b00000011);	// disable special register set

}

/**
 * @brief Initialize baud rate to 115200 and 8-N-1 by default
 *
 * @return true if success
 */
void read_divisor(uint8_t addr, int file){
	// int len;
	uint8_t lcr, data, val;	// dlh, dll,

	lcr = i2c_smbus_read_byte_data(file, REG_LCR);
	val = lcr | 0b10000000;	// Set LCR[7] = 1

	printf("REG_LCR: device 0x%02x at address 0x%02x: 0x%02x\n",
			addr, REG_LCR, lcr);

	write_byte(file, REG_LCR, val);		// Enables Register Set 2.

	data = i2c_smbus_read_byte_data(file, REG_DLL);
	printf("REG_DLL: 0x%02x at address 0x%02x: 0x%02x\n",
			addr, REG_DLL, data);
	data = i2c_smbus_read_byte_data(file, REG_DLH);
	printf("REG_DLH: 0x%02x at address 0x%02x: 0x%02x\n",
			addr, REG_DLH, data);

	val = lcr & 0b01111111;	// Set LCR[7] = 0
	write_byte(file, REG_LCR, val);

}

int main(int argc, char **argv)
{
	uint8_t addr = 0x48;	// data,
	uint8_t val = 65;	// ASCII value of "A"
	const char *path = argv[1];
	int file, rc;
	int len;

	if (argc == 1)
		errx(-1, "path [i2c address] [register]");

	// if (argc > 2)
	// 	addr = strtoul(argv[2], NULL, 0);
	// if (argc > 3)
	// 	reg = strtoul(argv[3], NULL, 0);

	file = open(path, O_RDWR);
	if (file < 0)
		err(errno, "Tried to open '%s'", path); 

	rc = ioctl(file, I2C_SLAVE, addr);
	if (rc < 0)
		err(errno, "Tried to set device address '0x%02x'", addr);

	read_divisor(addr, file);
	init_sc16is750(addr, file);
	read_divisor(addr, file);

	len = i2c_smbus_write_byte_data(file, REG_THR, val);
	if (len < 0)
		err(errno, "Tried to write data '0x%02x'", val);

	printf("%s: device 0x%02x at address 0x%02x: 0x%02x\n",
			path, addr, REG_THR, val);
}

