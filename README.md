# Casbin-rs Arangors adapter

## How to use
To make this crate work you need to create a collection named `casbin`.
Don't forget to put The unique key index on columns `ptype,v0,v1,v2,v3,v4,v5`

## Disclaimer

The crate is not 100% tested and will maybe have some bugs.
Feel free to make a push request to fix those bugs 😃.

The code can be improved for sure but it wasn't the main goal.


A lot of the code was taken from this repo: https://github.com/casbin-rs/diesel-adapter