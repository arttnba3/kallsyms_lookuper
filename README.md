# kallsyms_lookuper

Another tool for looking up kernel symbols by reading `/proc/kallsyms` directly from kernel space.

### How to use?

All you need to do is put the `klookuper` directory under your source code, add `klookuper/lookuper.o` into your `Kbuild/Makefile`, and then invoke this function after including the `lookuper.h` into your source code:

```c
extern int kallsyms_addr_lookup(const char *name,
                                size_t *res,
                                const char **ignore_mods,
                                const char *ignore_types);
```

For the parameters: 

- `name` : the name of the kernel symbol you'd like to search for.
- `res` : pointer to the variable provided by you to store the final value we got.
- `ignore_mods` : if not `NULL`, it should be a `char*` array ended with `NULL`, representing the mod that you'd like to ignore (as we may have same name for symbols in different modules). Note that the module name should be wrapped with `[]`.
- `ignore_types` : similar to `ignore_mods`, but it should be a `char` array ended with `\0`.

For the return value, `0` means successful, while other minus value indicates the error.

### Example

Following code is a simple example to find out kernel symbol `init_cred`, ignoring symbols in module `a3kmod` and type `t` :

```c
void foo(void)
{
    size_t ret;
    int err;
    const char *ignore_mods[] = {
        "[a3kmod]",
        NULL
    };
    const char ignore_types[] = {
        't', '\0'
    };

    err = kallsyms_addr_lookup("init_cred", &ret, ignore_mods, ignore_types);
    if (!err) {
        printk(KERN_INFO "[foo:] Got addr of [init_cred]: %lx\n", ret);
    } else {
        printk(KERN_ERR "[foo:] FAILED to get kernel symbol, errno: %d\n", err);
    }
}
```

You can refer to `demo_main.c` to get the basic usage, which is a simple demo for using the API we provided to read the specific kernel symbol.

### Author

arttnba3 <arttnba@gmail.com>

### License

GPL v2
