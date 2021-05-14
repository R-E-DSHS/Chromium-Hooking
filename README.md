# chrome hooker
 Chromium based browser hooking PoC
 
 - Using Detours
 - Working on Chromium based browser like Brave, Chrome, Edge etc.. (until 89.X)

# EV Code Sign 인증서
 Code Sign 인증서: 프로그램이 위조 등이 없었음을 증명하고 프로그램의 신뢰를 위해 사용. 일반, EV 두 종류가 있음.
 
 윈도우 XP 이후로 커널 드라이버를 로드하려면 EV 인증서를 필요로 하게 됨.
 커널 드라이버의 경우 윈도우의 전반적인 모든 부분에 접근함으로써 악용의 위협이 있기에 이를 반영한 결과.
 
 EV 인증서로 인증되지 않은 커널 드라이버를 로드하기 위해서는 bcdedit을 통해 Test Mode로 진입이 필요.
 결과적으로 배포가 사실상 불가능해짐.
 
 해당 프로젝트를 진행하며 개발한 드라이버를 배포, 피드백을 받으면 어떨까라는 의견이 나왔고 이를 위해서는 인증서가 필요.
 
 - Comodo
 - Digicert

 대표적인 인증서 제공사로 Comodo의 경우 년 315USD라는 비교적 저렴한 가격에 제공.

 추가적으로 커널 드라이버 인증 과정(Microsoft 제공)이 있지만 이는 추가적인 비용 요구, 필수 X.
 
 (해당 인증서 및 과정은 프로젝트 진행에 있어 무조건적으로 필수되지 않음.)
 

 
