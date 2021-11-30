# PCAPExtractor
pcap是Wireshark导出的一种常见文件类型

## 参考链接
1. https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/HTTPS-TLS1.2_handshake.md RFC文档中文翻译
2. https://datatracker.ietf.org/doc/html/rfc4346 各种Handshake报文格式的RFC文档
3. https://dpkt.readthedocs.io/en/latest/index.html DPKT官方文档
4. https://www.cnblogs.com/bonelee/p/10409176.html 参考的dpkt解析tls流的最原始代码
5. https://www.136.la/shida/show-304529.html 另一份相似的源码：SSL 流tcp payload和证书提取(示例代码)
6. https://www.it610.com/article/1238201870892199936.htm TLS Record Protocol报文格式很细致的中文讲解
7. https://blog.csdn.net/weixin_36139431/article/details/103541874 TLS握手过程
8. https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml TLS Cipher Suite对照表完整版
9. https://www.rfc-editor.org/rfc/rfc8701.html Cipher Suite的GREASE Values保留值：0xaaaa
10. https://www.cnblogs.com/yinghao-liu/p/7532889.html TCP segment of a reassembled PDU Wireshark的分段TCP协议问题
11. https://ask.wireshark.org/question/3498/what-is-the-difference-between-tcp-payload-and-tcp-segment-data/ TCP payload和TCP segment data的区别，它也没讲明白
12. https://www.cnblogs.com/kxdblog/p/4218028.html Wireshark的TCP乱序重组原理
13. https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html TCP Reassembly的英文参考
14. https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3 完整的handshake类型表