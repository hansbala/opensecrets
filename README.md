# OpenSecrets

OpenSecrets is a small CLI for protecting files inside an arbitrary folder with strong encryption and a password-based unlock flow.

## API

```bash
opensecrets init
opensecrets unlock
opensecrets unlock <path>...
opensecrets lock <path>...
opensecrets lock
```

## Examples

Initialize a protected folder:

```bash
opensecrets init
```

Start a local authenticated session:

```bash
opensecrets unlock
```

Unlock a file:

```bash
opensecrets unlock secrets/prod.env
```

Unlock a directory:

```bash
opensecrets unlock secrets/
```

Lock a file back into the encrypted store:

```bash
opensecrets lock secrets/prod.env
```

Lock a directory back into the encrypted store:

```bash
opensecrets lock secrets/
```

Go dark and clear the local session:

```bash
opensecrets lock
```

## License

OpenSecrets is licensed under the [MIT License](./LICENSE).
