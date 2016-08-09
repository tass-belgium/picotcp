picoTCP

---------------

Welcome to the one and only <font color=ff00f0>picoTCP repository</font>. 

picoTCP is a small-footprint, modular TCP/IP stack designed for embedded systems and the Internet of Things. It's actively being developed by *[Altran Intelligent Systems](http://intelligent-systems.altran.com/)*. Textual information about picoTCP, you can find on the [about page of our website](http://picotcp.com/about).

This code is released under the terms of GNU GPL v2 only. Some rights reserved.
Other licenses may apply at the sole discretion of the copyright holders.

Learn how to use picoTCP in your project by going through the **Getting Started guide** on our [GitHub wiki](https://github.com/tass-belgium/picotcp/wiki).

For more information visit the [picoTCP website](http://www.picotcp.com), send us an email or contact us on [Twitter](https://twitter.com/picotcp), [Facebook](https://www.facebook.com/picoTCP) or [Reddit](http://www.reddit.com/r/picotcp/).

Wondering about picoTCP's code quality? Check [our TiCS score](http://tics.picotcp.com:42506/tiobeweb/TICS/TqiDashboard.html#axes=Project%28%29&metric=tqi&sel=Project%28PicoTCP_rel%29)


---------------

Continuous integration

Jenkins Functional tests: 
[![Jenkins autotest](http://jenkins.picotcp.com:8080/buildStatus/icon?job=picoTCP_Rel/PicoTCP_rel_autotest)](http://jenkins.picotcp.com:8080/job/picoTCP_Rel/job/PicoTCP_rel_autotest)

Jenkins Unit tests      : 
[![Jenkins unit tests](http://jenkins.picotcp.com:8080/buildStatus/icon?job=picoTCP_Rel/PicoTCP_rel_unit_tests)](http://jenkins.picotcp.com:8080/job/picoTCP_Rel/job/PicoTCP_rel_unit_tests)

Jenkins RFC compliance  :
[![Jenkins RFC Compliance](http://jenkins.picotcp.com:8080/buildStatus/icon?job=picoTCP_Rel/PicoTCP_rel_RF_mbed)](http://jenkins.picotcp.com:8080/job/picoTCP_Rel/job/PicoTCP_rel_RF_mbed)

Jenkins TICS quality    :
[![Jenkins TICS](http://jenkins.picotcp.com:8080/buildStatus/icon?job=picoTCP_Rel/PicoTCP_rel_TICS)](http://jenkins.picotcp.com:8080/job/picoTCP_Rel/job/PicoTCP_rel_TICS/)

Coverity Scan Build status:
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7944/badge.svg)](https://scan.coverity.com/projects/7944)

---------------

Works with ...
## Platforms
* ARM Cortex-M series
    * ST Micro STM
    * NXP LPC
    * TI Stellaris
    * Freescale K64F
* ARM ARM9-series
    * ST Micro STR9
* Texas Instruments
    * MSP430
* Microchip
    * PIC24
* Atmel
    * AVR 8bit
* Linux
    * User space (TUN/TAP)
    * Kernel space
* Windows
    * User space (TAP)

## Network drivers
* BCM43362 (IEEE 802.11)
* MRF24WG (IEEE 802.11)
* LPC Ethernet ENET/EMAC (IEEE 802.3)
* Stellaris Ethernet (IEEE 802.3)
* STM32 Ethernet (IEEE 802.3)
* Wiznet W5100 (IEEE 802.3)
* USB CDC-ECM (CDC1.2)
* PPP
* Virtual drivers
    * TUN/TAP
    * VDE
    * Libpcap

## (RT)OSes
* No OS / Bare metal
* FreeRTOS
* mbed-RTOS
* Frosted
* linux / POSIX
* MS DOS
* MS Windows

## Libraries
* wolfSSL
* mbedTLS
* Mongoose RESTful library
* MicroPython
* HTTP library
* ZeroMQ (WIP)
* MQTT

## Compilers
* GCC
* Clang
* TCC
* ARM-RCVT
* IAR
* XC-16
* MSP-GCC
* AVR-GCC

Your favorite not in the list? Check out the wiki for information and examples on how to port picoTCP to a new platform!
