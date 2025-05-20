include $(TOPDIR)/rules.mk

PKG_NAME:=nf_wgobfs
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=sh0rch <sh0rch@iwl.dev>

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sh0rch/nf_wgobfs.git
PKG_SOURCE_VERSION:=main

PKG_BUILD_DEPENDS:=rust/host
PKG_USE_MIPS16:=0

include $(INCLUDE_DIR)/package.mk
#include $(INCLUDE_DIR)/cargo.mk

define Package/nf_wgobfs
  SECTION:=net
  CATEGORY:=Network
  TITLE:=NFQUEUE WireGuard obfuscator
  DEPENDS:=+libnetfilter-queue +libmnl +libnfnetlink
endef

define Package/nf_wgobfs/description
 A lightweight WireGuard packet obfuscator using NFQUEUE.
endef

define Package/nf_wgobfs/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/nf_wgobfs $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/nf_wgobfs
	$(INSTALL_CONF) ./files/config $(1)/etc/nf_wgobfs/config
endef

$(eval $(call BuildPackage,nf_wgobfs))
