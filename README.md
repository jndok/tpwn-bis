## tpwn-bis
This is a PoC for `cve-2015-5932` / `cve-2015-5847` / `cve-2015-5864`

Tested on 10.10.5, vulns are killed in 10.11

This is my first poc, and has been written only for fun.

This may cause a kernel panic once in a while. Why this happens is beyond my knowledge, at least for now. You can view a sample panic log in the `panic` file in this repo, I would appreciate if you can help me out fixing this!
Apparently seems something related to free blocks corruption, or block poisoning maybe? I recall `0xdeadbeef` being the poison value.

To trigger a certain kernel panic (at least on my machine this always works) do:

```
for run in {1..100}; do ./tpwn-bis; done;
```
Please remember that if not run multiple times in succession like with the command above, `tpwn-bis` has never caused a kernel panic.

## note
This is not weaponized yet! It only leaks the KASLR slide and exits. I will add stack pivoting soon.

## credits
All credits for CVEs go to [@qwertyoruiop](https://twitter.com/qwertyoruiop), original [`tpwn`](https://github.com/kpwn/tpwn) developer.
Also many thanks to him for helping me out a lot!
