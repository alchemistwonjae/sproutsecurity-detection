// 한국어 검색어 → 룰 제목에 쓰이는 영어 용어
export const SYN: Record<string, string[]> = {
  랜섬웨어: ['ransomware', 'ransom'],
  웹셸: ['webshell', 'web shell'],
  웹쉘: ['webshell', 'web shell'],
  자격증명: ['credential', 'lsass', 'mimikatz'],
  자격: ['credential'],
  비밀번호: ['password', 'credential'],
  패스워드: ['password', 'credential'],
  횡이동: ['lateral'],
  권한상승: ['privilege', 'elevation'],
  지속성: ['persistence'],
  난독화: ['obfuscat', 'encoded'],
  백도어: ['backdoor'],
  피싱: ['phishing'],
  레지스트리: ['registry'],
  스케줄: ['schtasks', 'scheduled task'],
  파워쉘: ['powershell'],
  파워셸: ['powershell'],
  취약점: ['cve', 'exploit'],
  익스플로잇: ['exploit'],
  악용: ['exploit'],
  방화벽: ['firewall'],
  클라우드: ['cloud', 'aws', 'azure', 'gcp'],
  리눅스: ['linux'],
  윈도우: ['windows'],
  맥: ['macos'],
  삭제: ['delete', 'remove'],
  우회: ['bypass', 'evasion'],
  탈취: ['dump', 'steal', 'credential'],
  덤프: ['dump'],
  원격: ['remote', 'rdp'],
  암호화: ['encrypt', 'ransom'],
};

export const expandWord = (w: string): string[] => {
  const out = [w];
  for (const [k, v] of Object.entries(SYN)) if (w === k || (w.length >= 2 && k.startsWith(w))) out.push(...v);
  return out;
};

/** 공백 단위 단어가 모두 (동의어 포함) hay 안에 있는지 */
export const matchQuery = (q: string, hay: string) =>
  q.split(/\s+/).filter(Boolean).every((w) => expandWord(w).some((x) => hay.includes(x)));

export const SUGGESTED = ['LSASS', 'PowerShell', 'ransomware', 'Mimikatz', '웹셸', 'Log4j'];
