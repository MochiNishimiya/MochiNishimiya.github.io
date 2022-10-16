---
title: "ASCIS 2022 - Faku"
date: 2022-10-16T01:11:28+07:00
draft: false
description: "Writeup một bài Reverse challenge trong SVATTT"
---

# Table of Contents
1. [Một vài lời nói đầu](#một-vài-lời-nói-đầu)
2. [Khởi đầu](#khởi-đầu)
3. [Phân tích](#phân-tích)
4. [Anti Debugger](#anti-debugger)

# Một vài lời nói đầu

Sinh viên an toàn thông tin năm nay mình thi cùng với team UIT.pawf3ct, và bài blog này sẽ nói về cách làm của mình cho bài Reverse tên Faku. Trong lúc thi mình đã đầu tư cả 5-6 tiếng vào bài này chỉ vì một lỗi sai vô cùng ngớ ngẩn, tuy vậy mình vẫn cảm thấy khá vui và vô cùng giải tỏa tinh thần khi tìm ra được flag bài này. Và mình cũng xin cảm ơn tác giả vì đã tạo ra một challenge chất lượng như thế.

# Khởi đầu

Đây là một file PE 32 bit, nên mình sẽ sử dụng IDA để phân tích.

![](https://i.imgur.com/bdeqI8t.png)

Đây là lỗi đầu tiên mình gặp được khi "F5" chương trình. Tới đây mình liền nhảy tới địa chỉ được thông báo lỗi để kiểm tra.

![](https://i.imgur.com/ZeyiJMo.png)

À, đây chỉ là một lệnh gọi hàm bình thường thôi, nhưng chương trình không decompile được vì chỗ này.  

Để có thể sửa được lỗi này, chúng ta cần phải có một chút kiến thức nhỏ về IDA. Khi vừa mở một file để phân tích trong IDA, chương trình sẽ không phân tích kĩ hoàn toàn 100% mà chỉ phân tích kĩ những hàm đang được disassemble. Trong trường hợp trên, tại địa chỉ `0x404A38` hàm mẹ gọi tới một hàm khác tên là `sub_404B64`, nhưng vì IDA tưởng rằng hàm `sub_404B64` có thể bị lỗi gì đó (vì chưa được phân tích kĩ càng) nên hàm mẹ cũng không được decompile.

Như vậy để sửa được trường hợp trên, ta cần IDA phân tích tất cả các hàm một cách cẩn thận. Để làm được điều này ta chọn option như hình bên dưới, lưu file C ở bất kì đâu và mọi chuyện sẽ được giải quyết.

 ![](https://i.imgur.com/KJSvh7Y.png)

Code nhìn sáng hơn hoàn toàn:

![](https://i.imgur.com/sG0BfSo.png)

Nhìn sơ code, chương trình yêu cầu chúng ta nhập input với độ dài là 30 bytes, và sẽ check xem đó có phải là flag đúng không, có vẻ đây là một bài keygen thuần túy, nhưng khi đi sâu vào các hàm thì mọi chuyện không dễ như vậy...

# Phân tích

Khi phân tích các bạn sẽ gặp rất nhiều những lần gọi hàm như thế này:  
`(*(void (__thiscall **)(_DWORD *, int))(*v6 + 4))(v6, v22);`  
Một trong những lí do chính là vì chương trình mình đang phân tích được viết bằng C++, và khả năng cao tác giả sử dụng kỹ thuật lập trình hướng đối tượng (Để hiểu rõ cách biểu diễn memory của kĩ thuật OOP trong C++, các bạn có thể xem [link](https://www.youtube.com/watch?v=o-FFGIloxvE) này).  

Nhìn code thêm một chút, mình khá chắc đây chính là đoạn check flag:

```c
v11 = (*(int (__thiscall **)(_DWORD *))(*v6 + 12))(v6);
    v12 = "[-] Correct!";
    if ( !v11 )
      v12 = "[!] Wrong!";
```

Tới đây mình chuyển sang debug để có thể hiểu rõ hơn về cách kiểm tra input.  

Khi bước vào hàm, nhìn mọi thứ có vẻ rất dài và có thể sẽ rất dễ làm nản chí các Reverser. Nhưng việc reverse hết tất cả các hàm là một cách tiếp cận không tốt khi khoảng thời gian cho phép là không nhiều, nên mình sẽ tiếp tục debug và theo dõi các input và output để "đoán" chức năng các hàm.

![](https://i.imgur.com/hky2eEw.png)

Mình sẽ chuyển sang ASM để có thể quan sát các input dễ hơn. Lúc này mình để ý được tới 2 input:

![](https://i.imgur.com/4giKvzw.png)  

![](https://i.imgur.com/UYXtKgC.png)

Hình trên là input nhập vào chương trình của mình, và hình dưới là một dãy bytes của chương trình. Chúng ta cần quan sát output của hàm:

![](https://i.imgur.com/LXuQWym.png)

Tới đây mình liền cảm giác đây là một phép nhân số lớn, mình liền check thử ngay lập tức

![](https://i.imgur.com/8Xaffep.png)

(Code nhìn khá xấu, nhưng lúc đó mình cần kết quả liền nên mình không quan tâm tới vấn đề code đẹp :vvv)  
Bingo! Vậy đây là một phép nhân số lớn. Mình đã làm tương tự với các hàm còn lại và đây là kết quả:

```c++
...
v1 = this;
v27 = this;
"eh vector constructor iterator"(v28, 0x10u, 3u, sub_4015D7, std::vector<WeaponName_t>::_Tidy);
v31 = 0;
v2 = multiply(v1 + 7, v22, v1 + 55);
v3 = v1 + 59;
LOBYTE(v31) = 1;
v4 = multiply(v1 + 11, v23, v1 + 59);
LOBYTE(v31) = 2;
v5 = plus((int)v2, v24, (int)v4);
v6 = v1 + 15;
LOBYTE(v31) = 3;
v1 += 63;
v7 = multiply(v6, v25, v1);
LOBYTE(v31) = 4;
v8 = minus((int)v5, v26, (int)v7);
LOBYTE(v31) = 5;
not_important(v28, (int)v8);
...
```

Tóm tắt luồng chương trình trên có thể nhìn giống như thế này:  

`input0 * const0 + input1 * const1 - input2 * const2`

Với `input0`, `input1`, `input2` là input chính của mình nhập vào và được tách ra làm 3 phần có độ dài là 10 bytes mỗi phần, `const0`, `const1`, `const2` là các hằng số của chương trình.

Tương tự với những 2 lần tiếp theo:  
`input0 * const3 + input1 * const4 + input2 * const5`  
`input0 * const6 - input1 * const7 - input2 * const8`  

Khúc cuối chương trình có đoạn so sánh kết quả:

![](https://i.imgur.com/SfHhz1f.png)

Tới đây ta quá rõ đây là một hệ phương trình ba ẩn. Tới đây mình chỉ việc lấy các hằng số ra và nhờ Crypto bên mình giải hệ phương trình giúp. Và kết quả là `FAKU{N3V3R_9onn4_91v3_yOU_uP!}`.

Nhưng khi mình thử chạy chương trình lúc debug và nhập flag này vào, kết quả trả về là `[-] Correct!`, và khi mình chạy chương trình không dùng debugger thì kết quả trả về là `[!] Wrong!`.

# Anti Debugger

Đây là một dấu hiệu rất rõ ràng chương trình có anti debugger. Nhưng làm sao để biết được đoạn code nào có kỹ thuật anti debugger? Nếu như hiểu đủ rõ chương trình này, chúng ta có thể để ý hầu như không thấy sự xuất hiện nào của kỹ thuật anti debugger trong chương trình chính. Tới đây mình đoán chắc có thể những hàm đó nằm trong hàm init.  

![](https://i.imgur.com/HFDvjiE.png)

Cụ thể các hàm init nằm ở địa chỉ `0x407190`

![](https://i.imgur.com/AUvogBI.png)

Khi mình kiểm tra các hàm, mình phát hiện tận 3 kỹ thuật anti debugger: `NtQueryInformationProcess`, `GetThreadContext` và `PEB` (Mình sẽ không giải thích các kĩ thuật anti debugger trên, các bạn đọc có thể tham khảo [tại đây](https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software))

> Lí do mình làm bài này lâu hơn mong đợi là bởi vì mình không đọc kĩ document của kĩ thuật anti debugger sử dụng hàm `NtQueryInformationProcess`, lúc thi mình cứ nghĩ kĩ thuật này check Remote Debugger nên mình đã bỏ qua một cách vô cùng ẩu, và đã ngốn gần 2-3 tiếng chỉ để phát hiện chỗ này :catcri:

Lúc này mình chỉ việc bypass những chỗ anti debugger trên, và các hằng số sẽ được thay đổi để khi giải hệ phương trình, kết quả sẽ là flag thật.

https://www.wolframalpha.com/input?i=systems+of+equations+calculator&assumption=%7B"F"%2C+"SolveSystemOf3EquationsCalculator"%2C+"equation1"%7D+->"56343458161852729254105+x+%2B+478723272345650765274709+y+-+94567434321898965414145+z+%3D+77205325028399246428625144727543316375512475203"&assumption="FSelect"+->+%7B%7B"SolveSystemOf3EquationsCalculator"%7D%7D&assumption=%7B"F"%2C+"SolveSystemOf3EquationsCalculator"%2C+"equation2"%7D+->"78727474361278163830903+x+%2B+410783650765476383014385+y+%2B+830705034123630301616189+z+%3D+576728373602368866029583485236697935421371408887"&assumption=%7B"F"%2C+"SolveSystemOf3EquationsCalculator"%2C+"equation3"%7D+->"-30361498905232129414361+x+%2B+436765070189432343616507+y+%2B+638561696369834745894383+z+%3D+443550489437008394034948849149808613388615954563"

`ASCIS{Cpp_1s_34SY_bUt_(TT_TT)}`


