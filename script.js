const form = document.querySelector(".registration-form");
const domainInput = document.querySelector("#domain-url");
const domainList = document.querySelector("[data-domain-list]");
const totalCount = document.querySelector("[data-total-count]");
const submitButton = document.querySelector("[data-submit-button]");
const formHint = document.querySelector("[data-form-hint]");
const serviceNameInput = document.querySelector("#service-name");
const serviceTypeInput = document.querySelector("#service-type");
const servicePurposeInput = document.querySelector("#service-purpose");
const navItems = document.querySelectorAll("[data-nav-target]");
const navGroup = document.querySelector("[data-nav-group]");
const navGroupToggle = document.querySelector("[data-nav-group-toggle]");
const pageShell = document.querySelector(".page-shell");
const sidebar = document.querySelector(".sidebar");
const sidebarToggle = document.querySelector("[data-sidebar-toggle]");
const views = document.querySelectorAll("[data-view]");
const selectedDomainBadge = document.querySelector("[data-selected-domain]");
const scanDomainSelect = document.querySelector("[data-scan-domain-select]");
const autoCheckDomainSelect = document.querySelector("[data-auto-check-domain-select]");
const manualCheckDomainSelect = document.querySelector("[data-manual-check-domain-select]");
const autoSelectedDomainBadge = document.querySelector("[data-auto-selected-domain]");
const manualSelectedDomainBadge = document.querySelector("[data-manual-selected-domain]");
const scanTrigger = document.querySelector("[data-scan-trigger]");
const scanResults = document.querySelector("[data-scan-results]");
const scanStatus = document.querySelector("[data-scan-status]");
const sessionCheckPathInput = document.querySelector("[data-session-check-path]");
const sessionCheckTrigger = document.querySelector("[data-session-check-trigger]");
const sessionCheckStatus = document.querySelector("[data-session-check-status]");
const sessionCheckResult = document.querySelector("[data-session-check-result]");
const scanSessionKeyInput = document.querySelector("[data-scan-session-key]");
const scanSessionInput = document.querySelector("[data-scan-session-value]");
const autoSessionKeyInput = document.querySelector("[data-auto-session-key]");
const autoSessionInput = document.querySelector("[data-auto-session-value]");
const manualSessionKeyInput = document.querySelector("[data-manual-session-key]");
const manualSessionInput = document.querySelector("[data-manual-session-value]");
const domainStatusItems = document.querySelectorAll("[data-status-domains]");
const scanStatusItems = document.querySelectorAll("[data-status-scan]");
const settingsStatusItems = document.querySelectorAll("[data-status-settings]");
const runStatusItems = document.querySelectorAll("[data-status-run]");
const completeStatusItems = document.querySelectorAll("[data-status-complete]");
const domainStatusSummary = document.querySelector("[data-status-domains-summary]");
const scanStatusSummary = document.querySelector("[data-status-scan-summary]");
const settingsStatusSummary = document.querySelector("[data-status-settings-summary]");
const completeStatusSummary = document.querySelector("[data-status-complete-summary]");
const domainStatusPercent = document.querySelector("[data-status-domains-percent]");
const scanStatusPercent = document.querySelector("[data-status-scan-percent]");
const settingsStatusPercent = document.querySelector("[data-status-settings-percent]");
const completeStatusPercent = document.querySelector("[data-status-complete-percent]");
const flowCards = document.querySelectorAll("[data-flow-step]");
const scanTitleValue = document.querySelector("[data-scan-title]");
const scanAssetsValue = document.querySelector("[data-scan-assets]");
const scanStackValue = document.querySelector("[data-scan-stack]");
const scanPathsValue = document.querySelector("[data-scan-paths]");
const scanTitleCopy = document.querySelector("[data-scan-title-copy]");
const scanAssetsCopy = document.querySelector("[data-scan-assets-copy]");
const scanStackCopy = document.querySelector("[data-scan-stack-copy]");
const scanPathsCopy = document.querySelector("[data-scan-paths-copy]");
const autoCheckResults = document.querySelector("[data-auto-check-results]");
const autoCheckStatus = document.querySelector("[data-auto-check-status]");
const manualVulnList = document.querySelector("[data-manual-vuln-list]");
const manualGuide = document.querySelector("[data-manual-guide]");
const manualRecords = document.querySelector("[data-manual-records]");
const manualCheckStatus = document.querySelector("[data-manual-check-status]");
const manualCheckForm = document.querySelector("[data-manual-check-form]");
const manualTargetLabel = document.querySelector("[data-manual-target-label]");
const manualParameterLabel = document.querySelector("[data-manual-parameter-label]");
const manualPayloadLabel = document.querySelector("[data-manual-payload-label]");
const manualTargetSelect = document.querySelector("[data-manual-target-select]");
const manualParameterSelect = document.querySelector("[data-manual-parameter-select]");
const manualTargetUrlInput = document.querySelector("#manual-target-url");
const manualParameterInput = document.querySelector("#manual-parameter");
const manualPayloadInput = document.querySelector("#manual-payload");
const manualVerdictInput = document.querySelector("#manual-verdict");
const manualRequestInput = document.querySelector("#manual-request");
const manualResponseInput = document.querySelector("#manual-response");
const manualNoteInput = document.querySelector("#manual-note");

const API_BASE_URL = String(import.meta.env.VITE_API_BASE_URL || "").trim().replace(/\/$/, "");

function apiUrl(path) {
  if (!API_BASE_URL) {
    return path;
  }

  return `${API_BASE_URL}${path}`;
}

let selectedItem = null;
let nextDomainId = 4;
let scanState = {};
const SIDEBAR_STATE_KEY = "vuln-check.sidebar-collapsed";
const SESSION_STATE_KEY = "vuln-check.session-state";
let sessionState = loadSessionState();
let selectedManualVuln = "SQL Injection";
const MANUAL_RECORDS_KEY = "vuln-check.manual-records";
let manualRecordsState = loadManualRecords();

const MANUAL_VULNS = [
  "SQL Injection",
  "XSS",
  "취약한 세션 관리",
  "취약한 계정 잠금 메커니즘",
  "접근 통제 실패",
  "CSRF",
  "파일 업로드 취약점",
  "파일 다운로드 취약점",
  "IDOR",
  "Open Redirect",
  "Path Traversal",
  "인증 우회",
  "쿠키 속성 취약점",
];

const MANUAL_GUIDES = {
  "SQL Injection": {
    focus: "검색, 조회, 정렬, 필터 파라미터",
    request: "단일 인용부호, 논리식, time-based payload를 순차 테스트",
    response: "SQL 오류, 지연, 우회, 레코드 수 변화 확인",
    targetLabel: "대상 URL",
    targetPlaceholder: "/search?q=",
    parameterLabel: "파라미터",
    parameterPlaceholder: "q, keyword, id",
    payloadLabel: "테스트 페이로드",
    payloadPlaceholder: "' OR '1'='1",
    requestPlaceholder: "GET /search?q=test HTTP/1.1\n쿠키 / 인증 헤더 포함 여부 기록",
    responsePlaceholder: "오류 메시지, 지연, 결과 수 변화, 우회 여부",
    notePlaceholder: "오류 기반 / blind / time-based 여부와 판정 근거",
  },
  XSS: {
    focus: "검색어, 게시물, 프로필, 리다이렉트 전후 출력 지점",
    request: "기본 script payload 대신 context별 안전한 테스트 문자열부터 확인",
    response: "반사/저장 여부, HTML escape 처리 여부, CSP 영향 확인",
    targetLabel: "출력 확인 URL",
    targetPlaceholder: "/board?query=",
    parameterLabel: "출력 파라미터",
    parameterPlaceholder: "query, content, title",
    payloadLabel: "테스트 문자열",
    payloadPlaceholder: "<xss-test>",
    requestPlaceholder: "입력 지점과 출력 지점을 함께 기록\n반사 / 저장 여부 구분",
    responsePlaceholder: "HTML escape 여부, DOM 삽입 여부, CSP 차단 여부",
    notePlaceholder: "반사형/저장형/DOM 기반 여부와 재현 위치",
  },
  "취약한 세션 관리": {
    focus: "세션 쿠키, 로그아웃, 세션 만료, 세션 고정",
    request: "로그인 전후 쿠키 변화와 재사용 가능 여부 확인",
    response: "HttpOnly, Secure, SameSite, 세션 재발급 여부 확인",
    targetLabel: "확인 URL",
    targetPlaceholder: "/login /mypage",
    parameterLabel: "세션 요소",
    parameterPlaceholder: "session cookie, auth cookie",
    payloadLabel: "확인 항목",
    payloadPlaceholder: "로그인 전후 쿠키 비교",
    requestPlaceholder: "로그인 전/후 요청, 로그아웃 후 재사용 요청 기록",
    responsePlaceholder: "Set-Cookie, 세션 재발급, 로그아웃 후 접근 가능 여부",
    notePlaceholder: "쿠키 속성, 만료, 고정 가능성 정리",
  },
  "취약한 계정 잠금 메커니즘": {
    focus: "로그인 실패 제한, CAPTCHA, 지연 정책",
    request: "잘못된 비밀번호 반복 시도",
    response: "계정 잠금, 지연, 차단 메시지 여부 확인",
    targetLabel: "로그인 URL",
    targetPlaceholder: "/login",
    parameterLabel: "계정 식별값",
    parameterPlaceholder: "username, email",
    payloadLabel: "반복 시도 조건",
    payloadPlaceholder: "동일 계정 5회 실패",
    requestPlaceholder: "실패 횟수별 요청을 순차 기록",
    responsePlaceholder: "잠금 메시지, 딜레이, CAPTCHA, 차단 상태",
    notePlaceholder: "실패 횟수 기준과 우회 가능 여부",
  },
  "접근 통제 실패": {
    focus: "일반 사용자/관리자 기능, 타 사용자 데이터",
    request: "권한이 낮은 계정으로 직접 URL 접근",
    response: "403 여부, 데이터 노출 여부, 기능 실행 여부 확인",
    targetLabel: "보호 리소스 URL",
    targetPlaceholder: "/admin/users/1",
    parameterLabel: "권한 차이",
    parameterPlaceholder: "일반 사용자 / 관리자",
    payloadLabel: "직접 접근 값",
    payloadPlaceholder: "다른 권한 계정으로 동일 요청",
    requestPlaceholder: "권한별 요청 헤더/쿠키를 함께 기록",
    responsePlaceholder: "403/302 여부, 데이터 노출, 기능 실행 결과",
    notePlaceholder: "권한 우회 가능 여부와 노출 범위",
  },
  CSRF: {
    focus: "상태 변경 요청, 프로필 수정, 결제, 설정 변경",
    request: "토큰 없이 동일 요청 재현 가능 여부 확인",
    response: "CSRF 토큰 검증, Origin/Referer 검증 여부 확인",
    targetLabel: "상태 변경 URL",
    targetPlaceholder: "/profile/update",
    parameterLabel: "변경 파라미터",
    parameterPlaceholder: "email, nickname, amount",
    payloadLabel: "검증 포인트",
    payloadPlaceholder: "토큰 제거 / Origin 제거",
    requestPlaceholder: "정상 요청과 토큰 제거 요청을 구분해 기록",
    responsePlaceholder: "토큰 검증 실패 여부, Origin/Referer 검사 여부",
    notePlaceholder: "동일 사이트/교차 사이트 요청 처리 차이 정리",
  },
  "파일 업로드 취약점": {
    focus: "첨부, 이미지 업로드, 문서 등록 기능",
    request: "확장자 우회, content-type 조작, 실행 가능 파일 업로드 여부 확인",
    response: "업로드 차단, 파일 실행 여부, 저장 경로 노출 여부 확인",
    targetLabel: "업로드 URL",
    targetPlaceholder: "/upload",
    parameterLabel: "업로드 필드",
    parameterPlaceholder: "file, image",
    payloadLabel: "파일 시나리오",
    payloadPlaceholder: "확장자 우회 / content-type 변경",
    requestPlaceholder: "업로드 파일명, 확장자, content-type 기록",
    responsePlaceholder: "업로드 허용 여부, 접근 URL, 실행 가능 여부",
    notePlaceholder: "검증 우회 / 실행 가능성 / 저장 경로 노출",
  },
  "파일 다운로드 취약점": {
    focus: "다운로드 파라미터, file/id/path 값",
    request: "다른 파일 식별자, 상위 경로 문자열 시도",
    response: "임의 파일 접근, 권한 없는 파일 다운로드 여부 확인",
    targetLabel: "다운로드 URL",
    targetPlaceholder: "/download?file=",
    parameterLabel: "파일 식별자",
    parameterPlaceholder: "file, path, id",
    payloadLabel: "테스트 값",
    payloadPlaceholder: "다른 파일 id / ../",
    requestPlaceholder: "정상 파일과 비정상 파일 식별자 요청 비교",
    responsePlaceholder: "권한 없는 파일 응답 여부와 파일 내용 확인",
    notePlaceholder: "임의 파일 접근 / 권한 우회 여부",
  },
  IDOR: {
    focus: "id, userId, orderId, fileId 등 객체 식별자",
    request: "다른 사용자 식별자로 직접 요청",
    response: "권한 검증 없이 데이터 열람/수정 가능 여부 확인",
    targetLabel: "객체 접근 URL",
    targetPlaceholder: "/orders/1001",
    parameterLabel: "식별자",
    parameterPlaceholder: "id, userId, orderId",
    payloadLabel: "변경 값",
    payloadPlaceholder: "다른 사용자 식별자",
    requestPlaceholder: "본인 식별자와 타인 식별자 요청을 구분해 기록",
    responsePlaceholder: "타인 데이터 조회/수정 성공 여부",
    notePlaceholder: "수평/수직 권한 우회 여부",
  },
  "Open Redirect": {
    focus: "redirect, next, returnUrl 파라미터",
    request: "외부 도메인 값을 넣어 리다이렉트 시도",
    response: "외부 이동 허용 여부와 whitelist 적용 여부 확인",
    targetLabel: "리다이렉트 URL",
    targetPlaceholder: "/login?next=",
    parameterLabel: "리다이렉트 파라미터",
    parameterPlaceholder: "next, redirect, returnUrl",
    payloadLabel: "외부 URL 값",
    payloadPlaceholder: "https://example.org",
    requestPlaceholder: "내부 URL과 외부 URL 값을 각각 요청",
    responsePlaceholder: "Location 헤더와 실제 이동 경로 확인",
    notePlaceholder: "외부 도메인 허용 여부와 우회 패턴",
  },
  "Path Traversal": {
    focus: "path, file, template, image 파라미터",
    request: "../ 패턴과 인코딩 패턴 시도",
    response: "상위 디렉터리 파일 접근 여부 확인",
    targetLabel: "파일 접근 URL",
    targetPlaceholder: "/view?path=",
    parameterLabel: "경로 파라미터",
    parameterPlaceholder: "path, file, template",
    payloadLabel: "경로 값",
    payloadPlaceholder: "../ 또는 인코딩 패턴",
    requestPlaceholder: "정상 경로와 상위 경로 시도를 구분해 기록",
    responsePlaceholder: "시스템 파일/상위 경로 접근 여부 확인",
    notePlaceholder: "정규화 우회 / 인코딩 우회 여부",
  },
  "인증 우회": {
    focus: "로그인, 비밀번호 재설정, 관리자 기능",
    request: "헤더/쿠키 제거, 비정상 흐름, 직접 URL 접근",
    response: "인증 없이 접근되거나 상태가 바뀌는지 확인",
    targetLabel: "인증 보호 URL",
    targetPlaceholder: "/admin",
    parameterLabel: "인증 요소",
    parameterPlaceholder: "cookie, auth header, reset token",
    payloadLabel: "우회 시나리오",
    payloadPlaceholder: "쿠키 제거 / 직접 URL 접근",
    requestPlaceholder: "정상 인증 요청과 비정상 흐름 요청을 비교",
    responsePlaceholder: "로그인 없이 접근/변경 가능 여부",
    notePlaceholder: "우회 경로와 재현 조건 정리",
  },
  "쿠키 속성 취약점": {
    focus: "세션 쿠키와 인증 쿠키",
    request: "로그인 전후 Set-Cookie 수집",
    response: "Secure, HttpOnly, SameSite 미설정 여부 확인",
    targetLabel: "쿠키 확인 URL",
    targetPlaceholder: "/login",
    parameterLabel: "쿠키 이름",
    parameterPlaceholder: "sessionid, auth_token",
    payloadLabel: "확인 항목",
    payloadPlaceholder: "Set-Cookie 속성 점검",
    requestPlaceholder: "로그인 전/후 응답 헤더를 수집",
    responsePlaceholder: "Set-Cookie의 Secure/HttpOnly/SameSite 확인",
    notePlaceholder: "쿠키 속성 누락과 영향 범위 정리",
  },
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function parseApiResponse(response) {
  const raw = await response.text();

  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    if (!response.ok) {
      if (response.status === 404 || raw.trim() === "Not Found") {
        throw new Error("현재 접속 중인 서버가 최신 버전이 아닙니다. 서버를 다시 실행하세요.");
      }
      throw new Error(raw || `request_failed:${response.status}`);
    }
    throw new Error("invalid_json_response");
  }
}

function domainRecords() {
  return [...document.querySelectorAll(".domain-item")].map((item) => ({
    id: item.dataset.domainId || "",
    domain: item.querySelector(".domain-value")?.textContent || "",
    serviceName: item.querySelectorAll(".domain-subvalue")[0]?.textContent || "",
    serviceType: item.querySelectorAll(".domain-subvalue")[1]?.textContent || "",
    servicePurpose: item.querySelectorAll(".domain-subvalue")[2]?.textContent || "",
  }));
}

function getSelectedDomain() {
  return scanDomainSelect?.value || selectedDomainBadge.textContent || "";
}

function loadSessionState() {
  try {
    const raw = window.localStorage.getItem(SESSION_STATE_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function saveSessionState() {
  window.localStorage.setItem(SESSION_STATE_KEY, JSON.stringify(sessionState));
}

function getCurrentSession(domain = getSelectedDomain()) {
  return sessionState[domain] || { key: "", value: "", checkPath: "" };
}

function buildSessionCookie(session) {
  if (!session?.key || !session?.value) {
    return "";
  }

  return `${session.key}=${session.value}`;
}

function syncSessionValue(session, persist = false) {
  const nextSession = {
    key: session?.key || "",
    value: session?.value || "",
    checkPath: session?.checkPath || getCurrentSession().checkPath || "",
  };

  if (scanSessionKeyInput && scanSessionKeyInput.value !== nextSession.key) {
    scanSessionKeyInput.value = nextSession.key;
  }
  if (scanSessionInput && scanSessionInput.value !== nextSession.value) {
    scanSessionInput.value = nextSession.value;
  }
  if (autoSessionKeyInput && autoSessionKeyInput.value !== nextSession.key) {
    autoSessionKeyInput.value = nextSession.key;
  }
  if (autoSessionInput && autoSessionInput.value !== nextSession.value) {
    autoSessionInput.value = nextSession.value;
  }
  if (manualSessionKeyInput && manualSessionKeyInput.value !== nextSession.key) {
    manualSessionKeyInput.value = nextSession.key;
  }
  if (manualSessionInput && manualSessionInput.value !== nextSession.value) {
    manualSessionInput.value = nextSession.value;
  }
  if (sessionCheckPathInput && sessionCheckPathInput.value !== nextSession.checkPath) {
    sessionCheckPathInput.value = nextSession.checkPath;
  }

  const domain = getSelectedDomain();
  if (persist && domain) {
    sessionState[domain] = nextSession;
    saveSessionState();
  }
}

function loadManualRecords() {
  try {
    const raw = window.localStorage.getItem(MANUAL_RECORDS_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function saveManualRecords() {
  window.localStorage.setItem(MANUAL_RECORDS_KEY, JSON.stringify(manualRecordsState));
}

function loadSidebarCollapsed() {
  try {
    return window.localStorage.getItem(SIDEBAR_STATE_KEY) === "true";
  } catch {
    return false;
  }
}

function applySidebarState(collapsed) {
  pageShell?.classList.toggle("is-sidebar-collapsed", collapsed);
  sidebar?.classList.toggle("is-collapsed", collapsed);
  if (sidebarToggle) {
    sidebarToggle.textContent = collapsed ? "메뉴 열기" : "메뉴 숨기기";
  }
}

function saveSidebarCollapsed(collapsed) {
  try {
    window.localStorage.setItem(SIDEBAR_STATE_KEY, collapsed ? "true" : "false");
  } catch {}
}

function syncSelectedDomain(domain) {
  const value = domain || "";

  if (selectedDomainBadge) {
    selectedDomainBadge.textContent = value || "선택 없음";
  }
  if (autoSelectedDomainBadge) {
    autoSelectedDomainBadge.textContent = value || "선택 없음";
  }
  if (manualSelectedDomainBadge) {
    manualSelectedDomainBadge.textContent = value || "선택 없음";
  }

  if (scanDomainSelect && scanDomainSelect.value !== value && [...scanDomainSelect.options].some((option) => option.value === value)) {
    scanDomainSelect.value = value;
  }
  if (
    autoCheckDomainSelect &&
    autoCheckDomainSelect.value !== value &&
    [...autoCheckDomainSelect.options].some((option) => option.value === value)
  ) {
    autoCheckDomainSelect.value = value;
  }
  if (
    manualCheckDomainSelect &&
    manualCheckDomainSelect.value !== value &&
    [...manualCheckDomainSelect.options].some((option) => option.value === value)
  ) {
    manualCheckDomainSelect.value = value;
  }

  syncSessionValue(getCurrentSession(value));
}

function createIndexLabel(index) {
  return String(index).padStart(2, "0");
}

function refreshIndexes() {
  document.querySelectorAll(".domain-item").forEach((item, index) => {
    const label = item.querySelector(".domain-index");
    if (label) {
      label.textContent = createIndexLabel(index + 1);
    }
  });
}

function updateCount() {
  totalCount.textContent = String(document.querySelectorAll(".domain-item").length);
}

function createDomainRow(record) {
  const item = document.createElement("tr");
  item.className = "domain-item";
  item.dataset.domainItem = "";
  item.dataset.domainId = record.id;

  const index = document.createElement("td");
  index.className = "domain-index";

  const value = document.createElement("td");
  value.className = "domain-value";
  value.textContent = record.domain;

  const serviceValue = document.createElement("td");
  serviceValue.className = "domain-subvalue";
  serviceValue.textContent = record.serviceName;

  const serviceTypeValue = document.createElement("td");
  serviceTypeValue.className = "domain-subvalue";
  serviceTypeValue.textContent = record.serviceType;

  const purposeValue = document.createElement("td");
  purposeValue.className = "domain-subvalue";
  purposeValue.textContent = record.servicePurpose;

  item.append(index, value, serviceValue, serviceTypeValue, purposeValue);
  attachItemEvents(item);
  return item;
}

function renderDomainTable(items) {
  if (!domainList) return;
  domainList.innerHTML = "";
  items.forEach((item) => {
    domainList.append(createDomainRow(item));
  });
  refreshIndexes();
  updateCount();
  updateDashboard();
  updateScanDomainOptions();
}

async function loadDomains() {
  try {
    const response = await fetch(apiUrl("/api/domains"), {
      headers: { Accept: "application/json" },
    });
    const payload = await parseApiResponse(response);
    if (!response.ok) {
      throw new Error(payload.message || "load failed");
    }
    const items = Array.isArray(payload.items) ? payload.items : [];
    renderDomainTable(items);
    const maxId = items.reduce((acc, item) => Math.max(acc, Number(item.id) || 0), 0);
    nextDomainId = maxId + 1;
  } catch (error) {
    console.error(error);
  }
}

async function saveDomainRecord(record) {
  const response = await fetch(apiUrl("/api/domains"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ item: record }),
  });

  const payload = await parseApiResponse(response);
  if (!response.ok) {
    throw new Error(payload.message || "save failed");
  }

  return payload.item;
}

async function loadScanResults() {
  const response = await fetch(apiUrl("/api/scans"), {
    headers: { Accept: "application/json" },
  });
  const payload = await parseApiResponse(response);
  if (!response.ok) {
    throw new Error(payload.message || "scan load failed");
  }

  const items = Array.isArray(payload.items) ? payload.items : [];
  scanState = items.reduce((acc, item) => {
    if (item.domain && item.result) {
      acc[item.domain] = {
        ...item.result,
        scannedAt: item.scannedAt || item.result.scannedAt || "",
      };
    }
    return acc;
  }, {});
}

async function saveScanResult(record) {
  const response = await fetch(apiUrl("/api/scans"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ item: record }),
  });

  const payload = await parseApiResponse(response);
  if (!response.ok) {
    throw new Error(payload.message || "scan save failed");
  }

  return payload.item;
}

async function verifySession(target, sessionValue, checkPath) {
  const response = await fetch(apiUrl("/api/session-check"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      target,
      sessionValue,
      checkPath,
    }),
  });

  const payload = await parseApiResponse(response);
  if (!response.ok) {
    throw new Error(payload.message || "session verify failed");
  }

  return payload;
}

function updateScanDomainOptions() {
  if (!scanDomainSelect && !autoCheckDomainSelect && !manualCheckDomainSelect) return;

  const domains = [...document.querySelectorAll(".domain-value")].map((item) => item.textContent || "");
  const current = selectedDomainBadge.textContent;
  if (!domains.length) {
    [scanDomainSelect, autoCheckDomainSelect, manualCheckDomainSelect].forEach((select) => {
      if (select) {
        select.innerHTML = `<option value="">등록된 도메인 없음</option>`;
      }
    });
    syncSelectedDomain("");
    return;
  }

  const selected = domains.includes(current) ? current : domains[0];
  const options = domains
    .map((domain) => {
      const value = escapeHtml(domain);
      return `<option value="${value}" ${domain === selected ? "selected" : ""}>${value}</option>`;
    })
    .join("");

  [scanDomainSelect, autoCheckDomainSelect, manualCheckDomainSelect].forEach((select) => {
    if (select) {
      select.innerHTML = options;
    }
  });
  syncSelectedDomain(selected);
}

function renderScanSummary(result) {
  if (scanTitleValue) {
    scanTitleValue.textContent = result?.page?.title || "-";
  }
  if (scanTitleCopy) {
    scanTitleCopy.textContent = result?.response?.finalUrl ? `현재 도달한 대표 페이지: ${result.response.finalUrl}` : "첫 응답 페이지의 제목입니다.";
  }
  if (scanAssetsValue) {
    const pages = result?.inventory?.pages?.length ?? 0;
    const endpoints = result?.inventory?.endpoints?.length ?? 0;
    const params = result?.inventory?.parameters?.length ?? 0;
    const patternEndpoints = (result?.inventory?.endpoints || []).filter((item) => item.source === "path-pattern").length;
    const scriptAssets = result?.inventory?.scripts?.length ?? 0;
    scanAssetsValue.textContent = `페이지 ${pages} / 엔드포인트 ${endpoints} / 파라미터 ${params}`;
    if (scanAssetsCopy) {
      scanAssetsCopy.textContent = params
        ? `외부 JS ${scriptAssets}개, 경로 패턴 ${patternEndpoints}개, 파라미터 ${params}개를 저장했습니다.`
        : `외부 JS ${scriptAssets}개까지 읽었지만 입력 파라미터는 아직 못 찾았습니다. 경로 패턴 ${patternEndpoints}개를 저장했습니다.`;
    }
  }
  if (scanStackValue) {
    const server = result?.stack?.server || "";
    const poweredBy = result?.stack?.poweredBy || "";
    const proxyOnly = ["istio-envoy", "cloudfront", "cloudflare", "awselb/2.0"].includes(server.toLowerCase());
    if (poweredBy && poweredBy !== "없음") {
      scanStackValue.textContent = poweredBy;
    } else if (server && server !== "없음" && !proxyOnly) {
      scanStackValue.textContent = server;
    } else if (proxyOnly) {
      scanStackValue.textContent = `프록시 식별 (${server})`;
    } else {
      scanStackValue.textContent = "추정 불가";
    }
    if (scanStackCopy) {
      scanStackCopy.textContent = proxyOnly
        ? "앱 서버보다는 앞단 프록시/CDN 정보가 먼저 보이는 상태입니다."
        : "응답 헤더에 노출된 서버 단서를 기반으로 표시합니다.";
    }
  }
  if (scanPathsValue) {
    const paths = result?.paths || [];
    const ok2xx = paths.filter((item) => typeof item.status === "number" && item.status >= 200 && item.status < 300).length;
    const redirects = paths.filter((item) => typeof item.status === "number" && item.status >= 300 && item.status < 400).length;
    const blocked = paths.filter((item) => item.status === 401 || item.status === 403).length;
    scanPathsValue.textContent = `2xx ${ok2xx} / 3xx ${redirects} / 차단 ${blocked}`;
    if (scanPathsCopy) {
      scanPathsCopy.textContent =
        redirects > 0
          ? "리다이렉트가 많아 실제 목적지 해석이 더 필요합니다."
          : "기본 후보 경로에 대한 직접 응답 상태를 요약한 값입니다.";
    }
  }
}

function getManualCandidates(domain, vuln) {
  const inventory = scanState[domain]?.inventory || { endpoints: [], parameters: [] };
  const interactiveEndpoints = inventory.endpoints.filter((item) => {
    const url = item.url || "";
    return !/\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff2?|map|json|txt|xml)$/i.test(url);
  });
  const usableParameters = inventory.parameters.filter((item) => {
    const name = item.name || "";
    return !/^(v\d+_|webpack|chunk|middleware|__|runtime|build|locale|lang|theme|color|size|width|height)$/i.test(name);
  });

  return {
    endpoints: interactiveEndpoints,
    parameters: usableParameters,
  };
}

function getManualParametersForTarget(candidates, targetUrl) {
  if (!targetUrl) {
    return candidates.parameters;
  }

  const relatedNames = new Set();
  candidates.endpoints
    .filter((item) => item.url === targetUrl)
    .forEach((item) => {
      (item.params || []).forEach((param) => relatedNames.add(param));
    });

  candidates.parameters.forEach((item) => {
    if ((item.endpoints || []).includes(targetUrl)) {
      relatedNames.add(item.name);
    }
  });

  if (!relatedNames.size) {
    return [];
  }

  return candidates.parameters.filter((item) => relatedNames.has(item.name));
}

function renderManualSuggestions(domain, record) {
  const candidates = getManualCandidates(domain, selectedManualVuln);
  const selectedTargetUrl =
    record?.targetUrl || manualTargetSelect?.value || manualTargetUrlInput?.value.trim() || candidates.endpoints[0]?.url || "";

  if (manualTargetSelect) {
    const targetOptions = candidates.endpoints.slice(0, 20);
    manualTargetSelect.innerHTML = targetOptions.length
      ? [`<option value="">수집된 URL 선택</option>`]
          .concat(
            targetOptions.map(
              (item) => `<option value="${escapeHtml(item.url)}">${escapeHtml(item.method)} ${escapeHtml(item.url)}</option>`,
            ),
          )
          .join("")
      : `<option value="">수집된 URL 없음</option>`;
  }

  const filteredParameters = getManualParametersForTarget(candidates, selectedTargetUrl);
  if (manualParameterSelect) {
    const parameterOptions = filteredParameters.slice(0, 20);
    manualParameterSelect.innerHTML = parameterOptions.length
      ? [`<option value="">수집된 파라미터 선택</option>`]
          .concat(parameterOptions.map((item) => `<option value="${escapeHtml(item.name)}">${escapeHtml(item.name)}</option>`))
          .join("")
      : `<option value="">수집된 파라미터 없음</option>`;
  }

  if (!record) {
    const firstParameter = filteredParameters[0];
    if (manualTargetUrlInput) {
      manualTargetUrlInput.value = selectedTargetUrl;
    }
    if (manualParameterInput) {
      manualParameterInput.value = firstParameter?.name || "";
    }
  }

  if (manualTargetSelect) {
    manualTargetSelect.value = selectedTargetUrl;
  }
  if (manualParameterSelect) {
    manualParameterSelect.value = record?.parameter || filteredParameters[0]?.name || "";
  }
}

function renderScanResults(domain) {
  if (!scanResults || !scanStatus) return;
  scanStatus.textContent = "스캔 완료";
  scanResults.innerHTML = domain.findings
    .map(
      (result) => `
        <article class="scan-result-item">
          <div class="scan-result-head">
            <span>${result.label}</span>
            <strong>${result.title}</strong>
            <div class="scan-result-meta">
              <em class="scan-verdict">${result.verdict || "정보"}</em>
              <p class="scan-evidence-inline">${result.evidence || "-"}</p>
            </div>
          </div>
          <div class="scan-result-grid">
            <div class="scan-result-block">
              <b>Request</b>
              <p>${result.request?.method || "-"} ${result.request?.url || ""}</p>
              <p>${(result.request?.headers || []).join("<br />") || "-"}</p>
            </div>
            <div class="scan-result-block">
              <b>Response</b>
              <p>Status: ${result.response?.status ?? "-"}</p>
              <p>${(result.response?.headers || []).join("<br />") || "-"}</p>
              <p>${result.response?.body || "-"}</p>
            </div>
          </div>
        </article>
      `,
    )
    .join("");
}

function deriveAutoCheckItems(result) {
  if (!result) {
    return [];
  }

  const headerMap = Object.fromEntries((result.headers || []).map(([name, value]) => [name, value]));
  const openPaths = result.openPaths || [];
  const adminExposure = openPaths.some((item) => item.includes("/admin") || item.includes("/api/docs"));
  const weakHeaders = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
  ].filter((name) => headerMap[name] === "없음");

  return [
    {
      label: "보안 헤더",
      verdict: weakHeaders.length ? "확인 필요" : "양호",
      detail: weakHeaders.length ? `누락: ${weakHeaders.join(", ")}` : "핵심 헤더가 확인되었습니다.",
    },
    {
      label: "TLS / HTTPS",
      verdict: result.response?.https ? "양호" : "취약",
      detail: result.response?.https ? "HTTPS 사용 중" : "HTTPS 미사용",
    },
    {
      label: "관리자 인터페이스 노출",
      verdict: adminExposure ? "확인 필요" : "양호",
      detail: adminExposure ? openPaths.join(", ") : "주요 관리자 경로 미탐지",
    },
    {
      label: "백업 / 공개 자산 노출",
      verdict: openPaths.some((item) => item.includes("robots.txt") || item.includes("sitemap.xml")) ? "확인 필요" : "양호",
      detail: openPaths.length ? openPaths.join(", ") : "기본 노출 경로 미탐지",
    },
    {
      label: "오류 / 서버 정보 노출",
      verdict: result.stack?.server && result.stack.server !== "없음" ? "확인 필요" : "양호",
      detail: result.stack?.server && result.stack.server !== "없음" ? `Server: ${result.stack.server}` : "서버 헤더 노출 미확인",
    },
  ];
}

function renderAutoCheckResults(result) {
  if (!autoCheckResults || !autoCheckStatus) {
    return;
  }

  const items = deriveAutoCheckItems(result);
  if (!items.length) {
    autoCheckStatus.textContent = "대기 중";
    autoCheckResults.innerHTML = `<div class="scan-result-empty">사이트 스캔을 완료하면 자동 점검 결과가 표시됩니다.</div>`;
    return;
  }

  const needReview = items.filter((item) => item.verdict !== "양호").length;
  autoCheckStatus.textContent = needReview ? "확인 필요 있음" : "양호";
  autoCheckResults.innerHTML = items
    .map(
      (item) => `
        <article class="scan-result-item auto-check-row">
          <span class="auto-check-label">${item.label}</span>
          <strong class="auto-check-verdict">${item.verdict}</strong>
          <p class="scan-evidence-inline auto-check-detail">${item.detail}</p>
        </article>
      `,
    )
    .join("");
}

function getManualRecordKey(domain, vuln) {
  return `${domain}::${vuln}`;
}

function renderManualVulnList() {
  if (!manualVulnList) {
    return;
  }

  manualVulnList.innerHTML = MANUAL_VULNS.map(
    (vuln) => `
      <button type="button" class="manual-vuln-chip ${vuln === selectedManualVuln ? "is-active" : ""}" data-manual-vuln="${escapeHtml(vuln)}">
        ${vuln}
      </button>
    `,
  ).join("");

  manualVulnList.querySelectorAll("[data-manual-vuln]").forEach((button) => {
    button.addEventListener("click", () => {
      selectedManualVuln = button.dataset.manualVuln || "SQL Injection";
      renderManualVulnList();
      renderManualGuide();
      renderManualRecord();
    });
  });
}

function renderManualGuide() {
  if (!manualGuide) {
    return;
  }

  const guide = MANUAL_GUIDES[selectedManualVuln] || MANUAL_GUIDES["SQL Injection"];
  const domain = getSelectedDomain();
  const candidates = getManualCandidates(domain, selectedManualVuln);
  manualGuide.innerHTML = `
    <article class="scan-result-item">
      <div class="scan-result-head">
        <span>수동 점검 가이드</span>
        <strong>${selectedManualVuln}</strong>
        <em class="scan-verdict">체크리스트</em>
      </div>
      <div class="scan-result-grid">
        <div class="scan-result-block">
          <b>확인 대상</b>
          <p>${guide.focus}</p>
        </div>
        <div class="scan-result-block">
          <b>요청 가이드</b>
          <p>${guide.request}</p>
        </div>
      </div>
      <div class="scan-result-note">
        <b>응답 확인 포인트</b>
        <p>${guide.response}</p>
      </div>
      <div class="scan-result-note">
        <b>스캔 기반 후보</b>
        <p>엔드포인트 ${candidates.endpoints.length}개 / 파라미터 ${candidates.parameters.length}개가 수집되어 수동 점검 입력에 활용됩니다.</p>
      </div>
    </article>
  `;
}

function applyManualTemplate(record) {
  const guide = MANUAL_GUIDES[selectedManualVuln] || MANUAL_GUIDES["SQL Injection"];

  if (manualTargetLabel) manualTargetLabel.textContent = guide.targetLabel || "대상 URL";
  if (manualParameterLabel) manualParameterLabel.textContent = guide.parameterLabel || "파라미터";
  if (manualPayloadLabel) manualPayloadLabel.textContent = guide.payloadLabel || "테스트 페이로드";

  if (manualTargetUrlInput) {
    manualTargetUrlInput.placeholder = guide.targetPlaceholder || "";
    if (!record) manualTargetUrlInput.value = "";
  }
  if (manualParameterInput) {
    manualParameterInput.placeholder = guide.parameterPlaceholder || "";
    if (!record) manualParameterInput.value = "";
  }
  if (manualPayloadInput) {
    manualPayloadInput.placeholder = guide.payloadPlaceholder || "";
    if (!record) manualPayloadInput.value = "";
  }
  if (manualRequestInput) {
    manualRequestInput.placeholder = guide.requestPlaceholder || "";
    if (!record) manualRequestInput.value = guide.requestPlaceholder || "";
  }
  if (manualResponseInput) {
    manualResponseInput.placeholder = guide.responsePlaceholder || "";
    if (!record) manualResponseInput.value = "";
  }
  if (manualNoteInput) {
    manualNoteInput.placeholder = guide.notePlaceholder || "";
    if (!record) manualNoteInput.value = guide.notePlaceholder || "";
  }
}

function renderManualRecord() {
  const domain = getSelectedDomain();
  const key = getManualRecordKey(domain, selectedManualVuln);
  const record = manualRecordsState[key];

  if (manualCheckStatus) {
    manualCheckStatus.textContent = domain ? `${selectedManualVuln}` : "대상 선택 필요";
  }

  applyManualTemplate(record);
  renderManualSuggestions(domain, record);

  if (manualTargetUrlInput && record) manualTargetUrlInput.value = record.targetUrl || "";
  if (manualParameterInput && record) manualParameterInput.value = record.parameter || "";
  if (manualPayloadInput && record) manualPayloadInput.value = record.payload || "";
  if (manualVerdictInput) manualVerdictInput.value = record?.verdict || "확인 필요";
  if (manualRequestInput && record) manualRequestInput.value = record.request || "";
  if (manualResponseInput && record) manualResponseInput.value = record.response || "";
  if (manualNoteInput && record) manualNoteInput.value = record.note || "";

  if (!manualRecords) {
    return;
  }

  if (!domain) {
    manualRecords.innerHTML = `<div class="scan-result-empty">도메인을 먼저 선택하세요.</div>`;
    return;
  }

  if (!record) {
    manualRecords.innerHTML = `<div class="scan-result-empty">${selectedManualVuln} 항목의 저장된 수동 점검 결과가 없습니다.</div>`;
    return;
  }

  manualRecords.innerHTML = `
    <article class="scan-result-item">
      <div class="scan-result-head">
        <span>${domain}</span>
        <strong>${selectedManualVuln}</strong>
        <div class="scan-result-meta">
          <em class="scan-verdict">${record.verdict}</em>
          <p class="scan-evidence-inline">${record.savedAt || ""}</p>
        </div>
      </div>
      <div class="scan-result-grid">
        <div class="scan-result-block">
          <b>Request</b>
          <p>URL: ${record.targetUrl || "-"}</p>
          <p>파라미터: ${record.parameter || "-"}</p>
          <p>페이로드: ${record.payload || "-"}</p>
          <p>세션 파라미터: ${record.sessionKey || "-"}</p>
          <p>세션 값: ${record.sessionValue || "-"}</p>
          <p>${record.request || "-"}</p>
        </div>
        <div class="scan-result-block">
          <b>Response</b>
          <p>${record.response || "-"}</p>
        </div>
      </div>
      <div class="scan-result-note">
        <b>메모</b>
        <p>${record.note || "-"}</p>
      </div>
    </article>
  `;
}

function renderStoredScanResult(domain) {
  const result = scanState[domain];
  if (!result) {
    scanStatus.textContent = "대기 중";
    scanResults.innerHTML = `
      <div class="scan-result-empty">도메인을 선택한 뒤 스캔을 실행하세요.</div>
    `;
    renderScanSummary(null);
    renderAutoCheckResults(null);
    renderManualRecord();
    return;
  }

  renderScanSummary(result);
  renderScanResults(result);
  renderAutoCheckResults(result);
  renderManualRecord();
}

async function executeScan(target) {
  if (!scanResults || !scanStatus) return;
  if (!target) {
    scanStatus.textContent = "대기 중";
    scanResults.innerHTML = `
      <div class="scan-result-empty">등록된 도메인을 먼저 추가하세요.</div>
    `;
    renderScanSummary(null);
    renderAutoCheckResults(null);
    return;
  }

  scanStatus.textContent = "스캔 중";
  scanResults.innerHTML = `
    <div class="scan-progress">
      <div class="scan-progress-head">
        <strong>스캔 진행 중</strong>
        <span>${target}</span>
      </div>
      <div class="scan-progress-bar" aria-hidden="true">
        <div class="scan-progress-fill"></div>
      </div>
      <p class="scan-progress-copy">라이트 크롤링과 엔드포인트 수집을 순차 실행하고 있습니다.</p>
    </div>
  `;

  try {
    const session = getCurrentSession(target);
    const sessionValue = buildSessionCookie(session);
    const response = await fetch(apiUrl("/api/scan"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ target, sessionValue }),
    });

    const result = await parseApiResponse(response);
    if (!response.ok) {
      throw new Error(result.message || "scan failed");
    }

    const savedResult = {
      ...result,
      scannedAt: new Date().toISOString(),
      sessionUsed: Boolean(sessionValue),
    };
    await saveScanResult({
      domain: target,
      scannedAt: savedResult.scannedAt,
      result: savedResult,
    });
    scanState[target] = savedResult;
    updateDashboard();
    renderScanSummary(savedResult);
    renderScanResults(savedResult);
    renderAutoCheckResults(savedResult);
  } catch (error) {
    scanStatus.textContent = "오류";
    scanResults.innerHTML = `
      <div class="scan-result-empty">스캔 중 오류가 발생했습니다: ${error.message}</div>
    `;
    renderScanSummary(null);
    renderAutoCheckResults(null);
  }
}

function updateDashboard() {
  const total = document.querySelectorAll(".domain-item").length;
  const records = domainRecords();
  const scan = records.filter((item) => Boolean(scanState[item.domain])).length;
  const settings = 0;
  const run = 0;
  const complete = 0;
  const percent = (value) => (total > 0 ? `${Math.round((value / total) * 100)}%` : "0%");

  domainStatusItems.forEach((item) => {
    item.textContent = String(total);
  });
  scanStatusItems.forEach((item) => {
    item.textContent = String(scan);
  });
  settingsStatusItems.forEach((item) => {
    item.textContent = String(settings);
  });
  runStatusItems.forEach((item) => {
    item.textContent = String(run);
  });
  completeStatusItems.forEach((item) => {
    item.textContent = String(complete);
  });

  if (domainStatusSummary) {
    domainStatusSummary.textContent = `${total}개`;
  }
  if (scanStatusSummary) {
    scanStatusSummary.textContent = `${scan}개`;
  }
  if (settingsStatusSummary) {
    settingsStatusSummary.textContent = `${settings}개`;
  }
  if (completeStatusSummary) {
    completeStatusSummary.textContent = `${complete}개`;
  }

  if (domainStatusPercent) {
    domainStatusPercent.textContent = percent(total);
  }
  if (scanStatusPercent) {
    scanStatusPercent.textContent = percent(scan);
  }
  if (settingsStatusPercent) {
    settingsStatusPercent.textContent = percent(settings);
  }
  if (completeStatusPercent) {
    completeStatusPercent.textContent = percent(complete);
  }
}

function setActiveView(target) {
  navItems.forEach((item) => {
    item.classList.toggle("is-active", item.dataset.navTarget === target);
  });

  if (navGroup) {
    navGroup.classList.toggle("is-open", target === "auto-check" || target === "manual-check");
  }

  views.forEach((view) => {
    view.classList.toggle("is-active", view.dataset.view === target);
  });

  const progressOrder = ["domains", "scan", "auto-check", "manual-check", "report"];
  const currentIndex = progressOrder.indexOf(target);

  flowCards.forEach((card) => {
    const stepIndex = progressOrder.indexOf(card.dataset.flowStep);
    card.classList.toggle("is-current", stepIndex === currentIndex);
    card.classList.toggle("is-done", stepIndex > -1 && stepIndex < currentIndex);
  });
}

function setEditingState(item) {
  document.querySelectorAll(".domain-item").forEach((domainItem) => {
    domainItem.classList.toggle("is-selected", domainItem === item);
  });

  selectedItem = item;

  if (!item) {
    form.reset();
    submitButton.textContent = "저장";
    formHint.textContent = "";
    updateScanDomainOptions();
    renderStoredScanResult(getSelectedDomain());
    return;
  }

  const value = item.querySelector(".domain-value")?.textContent || "";
  const metaItems = item.querySelectorAll(".domain-subvalue");
  const serviceText = metaItems[0]?.textContent || "";
  const serviceTypeText = metaItems[1]?.textContent || "";
  const purposeText = metaItems[2]?.textContent || "";
  domainInput.value = value;
  serviceNameInput.value = serviceText.trim();
  serviceTypeInput.value = serviceTypeText.trim();
  servicePurposeInput.value = purposeText.trim();
  selectedDomainBadge.textContent = value;
  updateScanDomainOptions();
  renderStoredScanResult(value);
  submitButton.textContent = "저장";
  formHint.textContent = "";
}

function attachItemEvents(item) {
  item.addEventListener("click", () => {
    setEditingState(item);
    const value = item.querySelector(".domain-value")?.textContent || "";
    syncSelectedDomain(value);
    renderStoredScanResult(value);
  });
}

form?.addEventListener("submit", async (event) => {
  event.preventDefault();

  const domain = domainInput?.value.trim();
  const serviceName = serviceNameInput?.value.trim() || "미정";
  const serviceType = serviceTypeInput?.value.trim() || "미정";
  const servicePurpose = servicePurposeInput?.value.trim() || "미정";
  if (!domain) {
    domainInput?.focus();
    return;
  }

  if (selectedItem) {
    const previousDomain = selectedItem.querySelector(".domain-value")?.textContent || "";
    const record = {
      id: selectedItem.dataset.domainId || "",
      domain,
      serviceName,
      serviceType,
      servicePurpose,
    };
    try {
      await saveDomainRecord(record);
    } catch (error) {
      formHint.textContent = `저장 실패: ${error.message}`;
      formHint.classList.remove("is-hidden");
      return;
    }

    const value = selectedItem.querySelector(".domain-value");
    const subvalues = selectedItem.querySelectorAll(".domain-subvalue");
    if (value) {
      value.textContent = domain;
    }
    if (subvalues[0]) {
      subvalues[0].textContent = serviceName;
    }
    if (subvalues[1]) {
      subvalues[1].textContent = serviceType;
    }
    if (subvalues[2]) {
      subvalues[2].textContent = servicePurpose;
    }
    if (previousDomain && previousDomain !== domain && scanState[previousDomain]) {
      scanState[domain] = scanState[previousDomain];
      delete scanState[previousDomain];
      saveScanResult({
        domain,
        scannedAt: scanState[domain].scannedAt || "",
        result: scanState[domain],
      }).catch(console.error);
    }
    syncSelectedDomain(domain);
    updateScanDomainOptions();
    setEditingState(null);
    refreshIndexes();
    updateCount();
    updateDashboard();
    renderStoredScanResult(domain);
    return;
  }

  const record = {
    id: String(nextDomainId),
    domain,
    serviceName,
    serviceType,
    servicePurpose,
  };
  nextDomainId += 1;
  try {
    await saveDomainRecord(record);
  } catch (error) {
    nextDomainId -= 1;
    formHint.textContent = `저장 실패: ${error.message}`;
    formHint.classList.remove("is-hidden");
    return;
  }

  const item = createDomainRow(record);
  domainList?.append(item);
  refreshIndexes();
  updateCount();
  updateDashboard();
  syncSelectedDomain(domain);
  updateScanDomainOptions();
  form.reset();
  formHint.textContent = "";
  formHint.classList.add("is-hidden");
  renderStoredScanResult(domain);
});

navItems.forEach((item) => {
  item.addEventListener("click", (event) => {
    event.preventDefault();
    const target = item.dataset.navTarget;
    if (target) {
      setActiveView(target);
    }
  });
});

navGroupToggle?.addEventListener("click", () => {
  navGroup?.classList.toggle("is-open");
});

sidebarToggle?.addEventListener("click", () => {
  const collapsed = !pageShell?.classList.contains("is-sidebar-collapsed");
  applySidebarState(collapsed);
  saveSidebarCollapsed(collapsed);
});

scanDomainSelect?.addEventListener("change", () => {
  syncSelectedDomain(scanDomainSelect.value);
  renderStoredScanResult(scanDomainSelect.value);
});

autoCheckDomainSelect?.addEventListener("change", () => {
  syncSelectedDomain(autoCheckDomainSelect.value);
  renderStoredScanResult(autoCheckDomainSelect.value);
});

manualCheckDomainSelect?.addEventListener("change", () => {
  syncSelectedDomain(manualCheckDomainSelect.value);
  renderStoredScanResult(manualCheckDomainSelect.value);
});

[sessionCheckPathInput].forEach((input) => {
  input?.addEventListener("input", () => {
    const domain = getSelectedDomain();
    if (domain) {
      sessionState[domain] = {
        ...(getCurrentSession(domain) || { key: "", value: "" }),
        checkPath: sessionCheckPathInput?.value.trim() || "",
      };
      saveSessionState();
    }
  });
});

[scanSessionKeyInput, scanSessionInput, autoSessionKeyInput, autoSessionInput, manualSessionKeyInput, manualSessionInput].forEach((input) => {
  input?.addEventListener("input", () => {
    syncSessionValue(
      {
        key: scanSessionKeyInput?.value || autoSessionKeyInput?.value || manualSessionKeyInput?.value || "",
        value: scanSessionInput?.value || autoSessionInput?.value || manualSessionInput?.value || "",
      },
      true,
    );
  });
});

manualTargetSelect?.addEventListener("change", () => {
  if (manualTargetUrlInput) {
    manualTargetUrlInput.value = manualTargetSelect.value;
  }
  renderManualSuggestions(getSelectedDomain());
});

sessionCheckTrigger?.addEventListener("click", async () => {
  const target = getSelectedDomain();
  const sessionCookie = buildSessionCookie(getCurrentSession(target));
  const checkPath = sessionCheckPathInput?.value.trim() || "/admin";

  if (!target || !sessionCookie) {
    if (sessionCheckStatus) {
      sessionCheckStatus.textContent = "입력 필요";
    }
    if (sessionCheckResult) {
      sessionCheckResult.innerHTML = `<div class="scan-result-empty">도메인, 세션 파라미터, 세션 값을 먼저 입력하세요.</div>`;
    }
    return;
  }

  if (sessionCheckStatus) {
    sessionCheckStatus.textContent = "확인 중";
  }
  if (sessionCheckResult) {
    sessionCheckResult.innerHTML = `<div class="scan-result-empty">세션 유효성을 확인하고 있습니다...</div>`;
  }

  try {
    const result = await verifySession(target, sessionCookie, checkPath);
    if (sessionCheckStatus) {
      sessionCheckStatus.textContent = result.verdict;
    }
    if (sessionCheckResult) {
      sessionCheckResult.innerHTML = `
        <article class="scan-result-item">
          <div class="scan-result-head">
            <span>세션 검증</span>
            <strong>${result.url}</strong>
            <div class="scan-result-meta">
              <em class="scan-verdict">${result.verdict}</em>
              <p class="scan-evidence-inline">${result.reason}</p>
            </div>
          </div>
          <div class="scan-result-grid">
            <div class="scan-result-block">
              <b>Response</b>
              <p>Status: ${result.status}</p>
              <p>Final URL: ${result.finalUrl}</p>
            </div>
            <div class="scan-result-block">
              <b>판정 기준</b>
              <p>${result.reason}</p>
            </div>
          </div>
        </article>
      `;
    }
  } catch (error) {
    if (sessionCheckStatus) {
      sessionCheckStatus.textContent = "오류";
    }
    if (sessionCheckResult) {
      sessionCheckResult.innerHTML = `<div class="scan-result-empty">세션 확인 중 오류가 발생했습니다: ${error.message}</div>`;
    }
  }
});

manualParameterSelect?.addEventListener("change", () => {
  if (manualParameterInput) {
    manualParameterInput.value = manualParameterSelect.value;
  }
});

manualCheckForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  const domain = getSelectedDomain();
  if (!domain) {
    return;
  }

  const key = getManualRecordKey(domain, selectedManualVuln);
  manualRecordsState[key] = {
    domain,
    vuln: selectedManualVuln,
    sessionCookie: buildSessionCookie(getCurrentSession(domain)),
    sessionKey: getCurrentSession(domain).key,
    sessionValue: getCurrentSession(domain).value,
    targetUrl: manualTargetUrlInput?.value.trim() || "",
    parameter: manualParameterInput?.value.trim() || "",
    payload: manualPayloadInput?.value.trim() || "",
    verdict: manualVerdictInput?.value || "확인 필요",
    request: manualRequestInput?.value.trim() || "",
    response: manualResponseInput?.value.trim() || "",
    note: manualNoteInput?.value.trim() || "",
    savedAt: new Date().toLocaleString("ko-KR"),
  };
  saveManualRecords();
  renderManualRecord();
});

scanTrigger?.addEventListener("click", () => {
  const target = scanDomainSelect?.value || selectedDomainBadge.textContent;
  syncSelectedDomain(target);
  executeScan(target);
});

Promise.all([loadDomains(), loadScanResults().catch(console.error)]).finally(() => {
  refreshIndexes();
  updateCount();
  updateDashboard();
  updateScanDomainOptions();
  renderManualVulnList();
  renderManualGuide();
  renderManualRecord();
  renderStoredScanResult(getSelectedDomain());
  applySidebarState(loadSidebarCollapsed());
  setActiveView("domains");
});
