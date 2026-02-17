
#
# Copyright (C) 2020 honwen (honwen.chan@gmail.com)
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=dnsproxy
PKG_VERSION:=2020-11-10
PKG_RELEASE:=0.33.2
PKG_MAINTAINER:=honwen (honwen.chan@gmail.com)

# OpenWrt ARCH: arm, aarch64, i386, x86_64, mips, mipsel
# Golang ARCH: arm6, arm64, 386, amd64, mips, mipsle
PKG_ARCH:=$(ARCH)
ifeq ($(ARCH),mipsel)
	PKG_ARCH:=mipsle
endif
ifeq ($(ARCH),i386)
	PKG_ARCH:=386
endif
ifeq ($(ARCH),x86_64)
	PKG_ARCH:=amd64
endif
ifeq ($(ARCH),arm)
	PKG_ARCH:=arm6
endif
ifeq ($(ARCH),aarch64)
	PKG_ARCH:=arm64
endif

PKG_SOURCE:=dnsproxy-linux-$(PKG_ARCH)-v$(PKG_RELEASE).tar.gz
PKG_SOURCE_URL:=https://github.com/AdguardTeam/dnsproxy/releases/download/v$(PKG_RELEASE)/
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_RELEASE)
PKG_HASH:=skip

include $(INCLUDE_DIR)/package.mk

define Package/dnsproxy
	SECTION:=net
	CATEGORY:=Network
	TITLE:=A simple DNS proxy server of AdguardTeam.
	URL:=https://github.com/AdguardTeam/dnsproxy
	DEPENDS:=+ca-bundle
endef

define Package/dnsproxy/description
	A simple DNS proxy server that supports all existing DNS protocols.
endef

define Build/Prepare
	gzip -dc "$(DL_DIR)/$(PKG_SOURCE)" | tar -C $(PKG_BUILD_DIR)/ -xf -
endef

define Build/Compile
	echo "$(PKG_NAME) Compile Skiped!"
endef

define Package/dnsproxy/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/dnsproxy.conf $(1)/etc/config/dnsproxy
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/dnsproxy.init $(1)/etc/init.d/dnsproxy
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/linux-$(PKG_ARCH)/dnsproxy $(1)/usr/bin/dnsproxy
endef

$(eval $(call BuildPackage,dnsproxy))
