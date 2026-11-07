## 编译

使用 Visual Studio 打开 `JiYuUdpTool.sln`，选择 `Release | x64` 后生成。输出位于 `x64/Release/JiYuUdpTool.exe`。项目使用 Windows SDK、Winsock 和 IP Helper API，不需要额外 C++ 库。

## 交互模式

双击 `x64/Release/JiYuUdpTool.exe`，依次输入：

```text
ip 192.168.80.1-254
ip 10.88.128./24
threads 64
scan
ip scan 10.88.128.1-255
wait
status
jobs
msg hello
command taskkill /F /IM notepad.exe
run C:\Windows\System32\notepad.exe
run "C:\Program Files\Example App\app.exe" --quiet
c rundll32.exe user32.dll,LockWorkStation
reboot
shutdown
wait
exit
```

`ip` 只选择后续命令的目标，不立即发送；支持单个 IPv4、同网段末段范围及 `/24`。`scan 10.88.128.1-255` 可直接扫描指定范围；单独输入 `scan` 会扫描当前选择的范围，不改变后续发送目标。扫描使用 ICMP Echo，只能说明主机响应了 ping，不能确认极域客户端或 UDP 服务是否运行；禁用 ICMP 的主机也可能漏报。当前 UDP 命令包没有文件传输协议，因此没有直接传文件的功能，文件收发需要接收端提供服务或另建传输通道。

`ip 10.88.128./24` 是 `ip 10.88.128.0/24` 的简写，两者都选择 `10.88.128.1` 到 `10.88.128.254`。`ip scan 10.88.128.1-255` 会在后台扫描，完成后仅选择响应 ICMP 的地址；随后用 `status` 可查看选中了多少个目标。扫描期间不能向这组目标发送，先用 `wait` 等待。若扫描期间又输入新的 `ip`，较新的设置优先，旧扫描结果不会覆盖它。`scan` 仍然只扫描，不改变选中目标。

`port 4705` 可更改端口；`status` 查看当前选择；`help` 查看所有指令。`command` 可缩写为 `c`，`reboot` 为 `r`，`shutdown` 为 `s`。`msg`、`command` 和 `run` 后可直接跟内容，也可以单独输入指令，等提示后在下一行输入内容。每条发送命令都使用上次选择的 IP 和端口；重新输入 `ip` 或 `port` 即可更改。`exit` 退出。此前的 `/ip` 等写法仍可使用。

交互模式下，`scan`、`msg`、`command`、`run`、`reboot` 和 `shutdown` 都作为后台任务启动，立即返回输入提示符。`jobs` 查看任务状态；`wait` 等待全部任务，`wait 1` 等待编号 1 的任务。最多同时运行 4 个后台任务；`exit` 会等待已启动的任务完成。`threads N` 设置每项任务的并发工作线程数（1-64，默认 64），扫描按 IP 并行，发送也按目标 IP 并行；同一项发送任务内，每个目标收到的数据包仍按原顺序发出。不同后台任务之间不保证同一目标的先后顺序，需要顺序时使用 `wait`。发送完成只表示 UDP 数据包已提交发送，不能确认对方执行了命令。

## 命令行模式

原有参数仍可使用：

```powershell
.\x64\Release\JiYuUdpTool.exe -h
.\x64\Release\JiYuUdpTool.exe -ip 192.168.80.12 -msg "hello"
.\x64\Release\JiYuUdpTool.exe -ip 192.168.80.12 -c "taskkill /F /IM notepad.exe"
.\x64\Release\JiYuUdpTool.exe -ip 192.168.80.12 -run "C:\Windows\System32\notepad.exe"
.\x64\Release\JiYuUdpTool.exe -ip 192.168.80.12 -c "rundll32.exe user32.dll,LockWorkStation"
.\x64\Release\JiYuUdpTool.exe -ip 192.168.80.12 -e r
.\x64\Release\JiYuUdpTool.exe -ip 192.168.80.12 -e s
.\x64\Release\JiYuUdpTool.exe -ip 192.168.80.23/24 -msg "hello" -l 3 -t 50
.\x64\Release\JiYuUdpTool.exe -ip 192.168.80.1-254 -j 32 -msg "hello"
```

`-ip` 指定单个 IPv4、末段范围或 `/24`；`-p` 默认 4705；`-msg` 发送消息；`-c` 发送命令；`-run` 直接运行程序；`-l` 和 `-t` 控制次数和间隔；`-e r/s` 分别发送重启和关机包。可以同时传 `-msg`、`-c`、`-run` 和一个 `-e` 模式，每轮按该顺序发送。

命令行模式的 `-j N` 设置每轮对不同 IP 的并发发送数（1-64，默认 64）；该模式仍会等发送完成后退出。

`-c` 不需要再写 `cmd /c`：原命令包已经包含 `C:\Windows\system32\cmd.exe` 和 `/c ` 前缀。`taskkill /F /IM notepad.exe` 会请求强制结束目标机的 `notepad.exe`；具体能否成功取决于目标进程的权限。`rundll32.exe user32.dll,LockWorkStation` 会请求锁定目标机的交互式桌面；若命令运行在服务会话等非交互环境，可能不会锁屏。

`run` 不经过 `cmd.exe`：第一个参数是目标机上的程序路径，其余部分是程序参数。路径含空格时用双引号包住，例如 `run "C:\Program Files\Example App\app.exe" --quiet`。`dir`、`cd` 等 CMD 内建命令仍应使用 `command`。此功能已验证发送包的字段布局，但没有目标客户端执行反馈，不能保证特定客户端版本接受这种直接运行形式。

Windows 7 到 Windows 11 的系统版本本身不是唯一条件：目标机还需安装能识别该 UDP 包格式的客户端、允许接收该端口的数据包，且启动程序的权限与会话条件满足要求。本项目没有对各版本目标客户端做实际兼容性验证，因此不承诺所有系统都能执行。

消息和命令按 UTF-16LE 写入原包模板。为保留终止符和后续字段，消息最多 448 个 UTF-16 代码单元，命令最多 156 个。过长输入会报错，不会截断或覆盖包内字段。
