# Authorized Keys module

*Note:* The `reset` command is not supported in the Authorized Keys module, you must delete and re-create a user's key file.

```
$ userplex authorizedkeys --help
NAME:
   userplex authorizedkeys - Operations within authorizedkeys files

USAGE:
   userplex authorizedkeys command [command options] [arguments...]

COMMANDS:
   create  Create user
   reset   Reset user credentials
   delete  Delete user
   sync    Run sync operation
   verify  Verify users against Person API. Outputs report, use `sync` to fix discrepancies.

OPTIONS:
   --help, -h  show help
```
