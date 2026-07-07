# Flow Logs on ADX 핸즈온 실습 가이드

> 범위: ADX 외부 테이블로 Storage에 저장된 VNet Flow Logs와 Virtual WAN Hub 진단 로그를 KQL로 쿼리·평탄화·조인하는 실습. **환경 구성(ADX 관리 ID 설정·역할 할당)부터** 외부 테이블 생성·평탄화·조인까지 순서대로 다룬다. 데모/교육용. KQL 예시는 로그 스키마 근거에 기반하되, 실제 환경에 맞게 경로·매핑을 조정해야 한다(일부 구문은 **예시/추론**으로 표기).

## 사전 준비 (Prerequisites)

이 실습은 **VNet Flow Logs가 이미 Storage Account에 JSON으로 적재되어 있다고 가정**하고, ADX 쪽 환경 구성(관리 ID → 역할 할당 → 정책 → 외부 테이블)부터 시작한다.

| 항목 | 상태 / 필요 조건 |
| --- | --- |
| VNet Flow Logs | **이미 Storage Account에 적재 완료(가정)**. Network Watcher에서 활성화되어 blob 컨테이너에 JSON으로 저장 중 (근거: Microsoft Learn "Virtual Network Flow Logs") |
| vHub 진단 로그 | (Lab 3용) Virtual WAN 게이트웨이 진단 설정 → Storage Account로 내보내기 |
| ADX 클러스터/DB | 무료 클러스터 또는 전용 클러스터에 DB 1개. Lab 0에서 관리 ID를 설정한다 |
| 권한(작업자) | ADX DB에 **Database Admin**(외부 테이블 생성) + Storage Account/구독에 **역할 할당 권한**(Owner 또는 User Access Administrator) 필요 (근거: Microsoft Learn "Authenticate external tables with managed identities" — Prerequisites; "Assign an Azure role for access to blob data") |

> **팁:** PoC는 ADX **무료 클러스터**로 충분하다. External Table은 데이터를 클러스터에 ingest하지 않으므로 저장 비용이 없다. (근거: Microsoft Learn "External tables - Kusto" — 외부 저장 데이터 대상)

---

## Lab 0. 환경 구성 — ADX 관리 ID & Storage 역할 할당

외부 테이블이 Storage의 VNet Flow Logs를 읽으려면 ADX 클러스터가 Storage에 인증할 수단이 필요하다. 여기서는 자격증명(SAS)을 코드에 두지 않는 **시스템 할당 관리 ID(System-assigned Managed Identity)** 방식을 사용한다. 순서는 **① 관리 ID 활성화 → ② 관리 ID 정책 설정 → ③ Storage 역할 할당**이다. (근거: Microsoft Learn "Authenticate external tables with managed identities")

### Lab 0-1. ADX 클러스터에 시스템 할당 관리 ID 활성화

Azure Portal에서 ADX 클러스터에 시스템 할당 ID를 켠다. (근거: Microsoft Learn "Configure managed identities for your Azure Data Explorer cluster" — Add a system-assigned identity)

1. Azure Portal에서 대상 **ADX 클러스터** 리소스를 연다.
2. 좌측 **Settings > Identity** 선택.
3. **System assigned** 탭에서 **Status** 슬라이더를 **On** → **Save** → 팝업에서 **Yes**.
4. 몇 분 뒤 표시되는 **Object (principal) ID**(GUID)를 복사해 둔다. → 이후 역할 할당·정책 확인에 사용.

> **참고:** 여러 클러스터에서 재사용하거나 수명주기를 분리하려면 **사용자 할당 관리 ID(User-assigned)** 도 가능하다. 이 경우 연결 문자열에 `;managed_identity=<objectId>` 형태로 Object ID를 지정한다. (근거: 같은 문서 — User-assigned)

### Lab 0-2. 외부 테이블용 관리 ID 정책 설정

관리 ID를 **외부 테이블 용도로 사용**하도록 클러스터(또는 DB) 관리 ID 정책을 설정한다. 이 명령이 없으면 관리 ID 인증 외부 테이블이 동작하지 않는다. (근거: Microsoft Learn "Authenticate external tables with managed identities" — 1. Configure a managed identity for use with external tables)

````kusto
.alter-merge cluster policy managed_identity ```[
    {
      "ObjectId": "system",
      "AllowedUsages": "ExternalTable"
    }
]```
````

> 특정 DB에만 적용하려면 `cluster` 대신 `database <DatabaseName>` 을 쓴다. 시스템 할당 ID는 `"ObjectId": "system"`, 사용자 할당 ID는 실제 Object ID를 지정한다. (근거: 같은 문서 — Note)

### Lab 0-3. Storage에 관리 ID 역할 할당 (Storage Blob Data Reader)

관리 ID가 Storage의 blob을 **읽을** 수 있도록 대상 Storage Account(또는 컨테이너) 범위에서 역할을 부여한다. 조회/쿼리는 **읽기** 권한이면 충분하므로 `Storage Blob Data Reader` 를 할당한다(내보내기·쓰기가 필요하면 `Storage Blob Data Contributor`). (근거: Microsoft Learn "Authenticate external tables with managed identities" — 2. Grant the managed identity external resource permissions 표)

Portal 방식:

1. 대상 **Storage Account**(또는 컨테이너)를 연다 → **Access Control (IAM)** → **Add > Add role assignment**.
2. **Role**: `Storage Blob Data Reader` 선택.
3. **Members**: **Managed identity** → 대상 ADX 클러스터의 시스템 할당 ID(클러스터 이름) 선택.
4. **Review + assign** 으로 저장.

CLI 방식(예시 — 값은 환경에 맞게 치환):

```bash
# ADX 클러스터의 시스템 할당 관리 ID Principal(Object) ID 조회
PRINCIPAL_ID=$(az kusto cluster show \
  --name <adxClusterName> \
  --resource-group <adxResourceGroup> \
  --query identity.principalId -o tsv)

# Storage Account 범위에 Storage Blob Data Reader 역할 할당
az role assignment create \
  --assignee-object-id "$PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Reader" \
  --scope "/subscriptions/<subId>/resourceGroups/<storageRG>/providers/Microsoft.Storage/storageAccounts/<storageAccount>"
```

> 역할 전파에는 보통 수 분이 걸린다. 할당 직후 외부 테이블 쿼리가 `403 Forbidden` 이면 잠시 후 재시도한다. (추론 — Azure RBAC 전파 지연 일반 특성)

---

## Lab 1. 외부 테이블 만들기 (VNet Flow Logs)

VNet Flow Logs blob 컨테이너를 원본(raw) 외부 테이블로 등록한다. 로그는 `{"records":[...]}` 형태의 JSON이므로, 우선 `records`를 dynamic으로 읽는다. 인증은 Lab 0에서 설정한 **시스템 할당 관리 ID**를 쓴다(연결 문자열 끝의 `;managed_identity=system`). (근거: Microsoft Learn — Sample log record 구조; "Authenticate external tables with managed identities" — 3. Create an external table)

```kusto
// 경로는 환경에 맞게 수정. 인증은 Lab 0의 시스템 할당 관리 ID 사용
.create external table VNetFlowRaw (records: dynamic)
kind = storage
dataformat = multijson
(
   h@'https://<storage>.blob.core.windows.net/<container>;managed_identity=system'
)
```

> 연결 문자열의 `;managed_identity=system` 은 시스템 할당 ID 인증을 의미한다. 사용자 할당 ID면 `;managed_identity=<objectId>` 로 지정한다. `dataformat`·파티셔닝·경로 패턴 등 정확한 구문은 "Create or alter Azure Blob Storage/ADLS external tables" 문서를 따른다. (근거: Microsoft Learn "Authenticate external tables with managed identities" — 연결 문자열 예시; "External tables - Kusto" — 생성 명령) — 경로는 **예시**이므로 실제 배포 시 검증 필요.

확인:

```kusto
external_table('VNetFlowRaw')
| take 10
```

---

## Lab 2. 중첩 JSON 평탄화 & flowTuples 파싱

`records → flowRecords.flows → flowGroups → flowTuples`를 펼치고, 콤마 구분 튜플을 컬럼으로 분해한다. flowTuples 필드 순서는 문서 기준이다. (근거: Microsoft Learn — Log format)

```kusto
external_table('VNetFlowRaw')
| mv-expand record = records
| extend flowLogVersion = record.flowLogVersion,
         targetResourceID = tostring(record.targetResourceID),
         mac = tostring(record.macAddress)
| mv-expand flow = record.flowRecords.flows
| extend aclID = tostring(flow.aclID)
| mv-expand fg = flow.flowGroups
| extend rule = tostring(fg.rule)
| mv-expand tuple = fg.flowTuples          // 콤마 구분 문자열
| extend p = split(tostring(tuple), ',')
| project
    timestamp   = unixtime_seconds_todatetime(tolong(p[0])),
    srcIp       = tostring(p[1]),
    dstIp       = tostring(p[2]),
    srcPort     = toint(p[3]),
    dstPort     = toint(p[4]),
    protocol    = toint(p[5]),             // 6=TCP, 17=UDP
    direction   = tostring(p[6]),          // I / O
    flowState   = tostring(p[7]),          // B / C / E / D
    encryption  = tostring(p[8]),          // X / NX ...
    packetsSent = tolong(p[9]),
    bytesSent   = tolong(p[10]),
    packetsRecv = tolong(p[11]),
    bytesRecv   = tolong(p[12]),
    rule, aclID, targetResourceID
```

> flowTuples의 Time Stamp는 UNIX epoch, direction은 `I`(inbound)/`O`(outbound), state는 `B/C/E/D`(begin/continuing/end/deny). (근거: Microsoft Learn — Log format)

**분석 예시 — 차단(deny)된 트래픽 Top 10 출발지:**

```kusto
external_table('VNetFlowRaw')
| mv-expand record = records
| mv-expand flow = record.flowRecords.flows
| mv-expand fg = flow.flowGroups
| mv-expand tuple = fg.flowTuples
| extend p = split(tostring(tuple), ',')
| where tostring(p[7]) == 'D'              // Flow state = Deny
| summarize denies = count() by srcIp = tostring(p[1])
| top 10 by denies desc
```

---

## Lab 3. 이종 로그 조인 (VNet Flow ↔ vHub 진단)

vHub 진단 로그(예: RouteDiagnosticLog/TunnelDiagnosticLog)를 별도 외부 테이블로 등록한 뒤, 시간·IP 기준으로 조인해 상관분석한다. (근거: Microsoft Learn "Monitoring data reference for Azure Virtual WAN" — Resource logs; VNet Flow의 5-tuple)

```kusto
// vHub 터널/라우팅 로그 외부 테이블 (예시 스키마)
let vhub = external_table('VHubDiagRaw')
    | mv-expand r = records
    | project t = todatetime(r.time),
              category = tostring(r.category),   // TunnelDiagnosticLog 등
              remoteIp = tostring(r.properties.remoteIP),
              msg = tostring(r.properties.message);
let flows = external_table('VNetFlowRaw')
    | mv-expand record = records
    | mv-expand flow = record.flowRecords.flows
    | mv-expand fg = flow.flowGroups
    | mv-expand tuple = fg.flowTuples
    | extend p = split(tostring(tuple), ',')
    | project t = unixtime_seconds_todatetime(tolong(p[0])),
              srcIp = tostring(p[1]), dstIp = tostring(p[2]),
              state = tostring(p[7]);
flows
| where state == 'D'
| join kind=inner (vhub) on $left.srcIp == $right.remoteIp
| where abs(datetime_diff('second', t, t1)) < 300   // ±5분 상관
| project flowTime = t, srcIp, dstIp, category, msg
```

> vHub 진단 로그의 정확한 `properties` 필드는 카테고리별로 다르며 `AzureDiagnostics` 스키마를 따른다. 위 스키마·필드명은 **예시**이므로 실제 로그로 검증 필요. (근거: Microsoft Learn — Resource logs 테이블은 AzureDiagnostics)

---

## Lab 4. (선택) 성능 가속 — Ingest 후 쿼리

자주 조회하는 기간의 데이터는 외부 테이블에서 ADX 테이블로 ingest해 인덱싱/캐싱으로 가속한다.

```kusto
.set-or-append FlowParsed <|
external_table('VNetFlowRaw')
| mv-expand record = records
| mv-expand flow = record.flowRecords.flows
| mv-expand fg = flow.flowGroups
| mv-expand tuple = fg.flowTuples
| extend p = split(tostring(tuple), ',')
| project timestamp = unixtime_seconds_todatetime(tolong(p[0])),
          srcIp = tostring(p[1]), dstIp = tostring(p[2]),
          dstPort = toint(p[4]), flowState = tostring(p[7])
```

> **판단 기준(추론):** 원시 저장소 즉시 쿼리(=Athena형)는 탐색/애드혹에 유리, 반복·대시보드성 쿼리는 ingest 가속이 유리. 하이브리드로 운영 권장.

## 정리 (Cleanup)

```kusto
.drop external table VNetFlowRaw
.drop external table VHubDiagRaw
```

> 필요 시 Lab 0에서 부여한 리소스도 정리한다: Storage의 `Storage Blob Data Reader` 역할 할당 제거, 관리 ID 정책 원복, 클러스터 시스템 할당 ID **Off**. (근거: Lab 0 설정 항목 역순)

## 미해결 / 검증 필요

- 관리 ID 인증 외부 테이블을 `.create-or-alter` 로 만들 때 필요한 권한 수준(Database Admin vs AllDatabasesAdmin)은 배포 환경에서 확인. (근거: Microsoft Learn "Authenticate external tables with managed identities" — Prerequisites는 Database Admin; delta 외부 테이블 문서는 AllDatabasesAdmin 언급 — 상충 가능, 검증 필요)
- 역할 할당 전파 지연으로 초기 쿼리가 `403` 일 수 있으므로 재시도 정책 확인.
- 외부 테이블 생성 구문(`dataformat`, 파티셔닝, 경로 패턴)은 실제 배포로 검증.
- vHub 진단 로그의 카테고리별 `properties` 스키마 확정 필요.
- 대용량 blob에서 `mv-expand` 다단계의 성능 영향 측정 필요.
