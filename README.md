# remora

This tools for increase awareness go engineer from vulnerability on standard libary or third-party.
Many engineers only remember when installing or adding third-party but after that forget to always check the vuln on the installed third-party.

## how to use:
you can install:
```shell
go install github.com/born2ngopi/remora
```
or clone and build
``` shell
git clone github.com/born2ngopi/remora && cd remora
--
go build -o remora *.go
```

to runing only on terminal
```shell
remora
```
and you got result:
![img](./media/result.png)

to set up githook
``` shell
curl -sSL https://raw.githubusercontent.com/born2ngopi/remora/refs/heads/master/script/pre-push.sh | bash
```

The deference between with and without `--git-hook` is how application stop/quit. 
When --git-hook and if any critycal or, >4 high or >6 medium severity the application will stop os.Exist(1).
Then you can handle the logic.
