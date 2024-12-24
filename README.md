# remora

This tools for increase awernes go engineer from vulnerability on standard libary or threedparty.
Many engineers only remember when installing or adding threedparty but after that forget to always check the vuln on the installed threedparty.

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

or if u running on git hooks you can add args `-githook=true`.

example use on git pre-push hook
```bash
#!/bin/bash

remora -githook=true

if [ $? -eq 1 ]; then
    echo "Check lagi Cuy, install mulu ngga maintenance"
    exit 1  
fi

exit 0
```

the deference between with and without `-githook=true` is how application stop/quit. 
when -githook=true and if any critycal or, >4 high or >6 medium severity the application will stop os.Exist(1).
then you can handle the logic