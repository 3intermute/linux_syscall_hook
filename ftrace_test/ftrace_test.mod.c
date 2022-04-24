#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0x581b1365, "module_layout" },
	{ 0x59fe70a8, "ftrace_set_filter_ip" },
	{ 0xe037666e, "unregister_ftrace_function" },
	{ 0xe0c7e9c6, "register_ftrace_function" },
	{ 0xaa9bddd8, "ftrace_set_filter" },
	{ 0x98cf60b3, "strlen" },
	{ 0xeb3f8466, "unregister_kprobe" },
	{ 0x3ce77caf, "register_kprobe" },
	{ 0x1fdc7df2, "_mcount" },
	{ 0xc5850110, "printk" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "A53999B8D7A275F9E481AF9");