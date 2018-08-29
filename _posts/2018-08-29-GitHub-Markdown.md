---
title: GitHub-Markdown基本语法
date: 2018-08-29
tags: Markdown
layout: post
---
# 基础写作和语法格式:


# 标题

Markdown中标题如果想定义一个标题，可以在前面加上#(或者用#将标题括起来)。1-6个#分别表示1-6级标题。有的编辑器需要在#和正文之间加一个空格(Atom)，有的编译器不用(MarkdownPad)，为了保持同一建议都加上空格。
```
写法一：
一级标题
========
二级标题
-------

写法二：
# 标题一
# 标题一#
## 二级标题
### 三级标题
#### 四级标题
##### 五级标题
```
显示结果：
### **写法一：**
  一级标题
==========
  二级标题
---------
------------------
### **写法二：**
# 标题一
# 标题一#
## 二级标题
### 三级标题
...
---
# 文本样式

Markdown支持4中文本样式，分别是：加粗、斜体、删除线和加粗且斜体。

|样式    |关键字           |样例                     |输出                   |
|:-------|:---------------|:------------------------|:---------------------|
|加粗    |`** **`或者__ __ |`**加粗文本**`            |**加粗文本**          |
|斜体    |` 	* *`或者`_ _`|` _斜体文本_`             |_斜体文本_            |
|删除线   |`~~ ~~`         |`~~删除线~~`              |~~删除线~~           |
|加粗且斜体|`** **和_ _`     |`**这个是：_加粗且斜体_**`|**_这个是_加粗且斜体**|

# 表格


```
|A|B|C|
|-:-|-:-|-:-|
|1|2|3|
```
结果：

|A|B|C|
|-:-|-:-|-:-|
|1|2|3|
## 第一行为表头，第二行为分割表头和主体。
对齐格式为：
```
- 默认左对齐
:- 左对齐
-: 右对齐
:-:居中对齐
```


# 引用文本

引用文本的关键字是**>** 。
```
下面是一个引用：
>这是一个引用。
```
输出结果：

下面是一个引用：

>这是一个引用。

# 引用代码

引用代码有两种形式，一种是在文本中引入一个代码：使用一个倒引号**`** 括起来；另一种是插入一段代码：使用三个倒引号`\`\`\`` 括起来(非标准Markdown语法,Atom中支持MarkdownPad中不支持)。

文中插入快捷键\`ctrl+v\`.

结果：

在文中插入快捷键`ctrl+v`.
```
我需要引用一段代码：  
\`\`\` c++
int a = 1;
int b = 2;
int c = a+b;
\`\`\`
```
结果：

我需要引用一段代码：
```
int a = 1;
int b = 2;
int c = a+b;
```
上面可以直接在三个倒引号后面加入引用代码的语言类型。编辑器会对应的进行渲染。当然我们也可以直接使用一个tab或四个空格来表示我要插入一段代码（Atom中是2个tab）。
```
  int a = 1;
  int b = 2;
  int c = a+b;
```
结果：

    int a = 1;
    int b = 2;
    int c = a+b;

# 链接

Git编译器关于链接的使用加入了较多的扩展。这里仅介绍标准Markdown语法中的行内链接和参考链接。
下面是行内链接示例：

`[链接到DA1SY](https://da1sy.github.io "DA1SY")  `

结果：

[连接到DA1SY](https://da1sy.github.io "DA1SY")

下面是一个参考链接的示例：
```
[链接到百度][1]
[链接到Google][2]  
[还是链接到百度][1]

[1]:https://www.baidu.com  
[2]:https://www.google.com  
```
结果：

[链接到百度][1]
[链接到Google][2]  
[还是链接到百度][1]

[1]:https://www.baidu.com  
[2]:https://www.google.com  

参考链接中的标号1,2不仅仅可以是数字，也可以是字母或它们的组合。
同时链接也支持相对路径，./表示当前目录，../表示前一级目录。这里也建议在编写文档时，不同文档之间的关联采用相对路径的形式。

# 列表

我们可以使用*,+,-或者数字作为列表的关键字。同时列表也支持嵌套的形式。
```
- 主列表1
- 主列表2
  1. 次列表1
  2. 次列表2
+ 主列表3
```
结果：

- 主列表1
- 主列表2
  1. 次列表1
  2. 次列表2
+ 主列表3

# 任务列表

任务列表是Git对标准Markdown语法的扩展，并不是标准Markdown语法。因此MarkdownPad不会对该语法进行渲染。但是使用Atom就会对该语法进行渲染。
```
- [x] 任务列表1
- [ ] 任务列表2
- [ ] 任务列表3
```
结果：

- [x] 任务列表1
- [ ] 任务列表2
- [ ] 任务列表3

# 使用表情

Git中的Markdown语法扩展中包括了一些表情包。这个表情包语法依然可以通过Atom进行渲染。由于不是标准的Markdown语法不能通过MarkdownPad渲染。
```
表情一：:+1:,表情二：:o:
```
表情一：:+1:,表情二：:o:

# **忽略关键字**
```
 \*\*取消Markdown关键字
```
输出结果:

 \*\*取消Markdown关键字