# Azure Data Explorer (ADX) — AWS 사용자를 위한 핵심 가이드

> 범위: AWS에는 익숙하지만 Azure는 처음인 사용자를 위해, Azure Data Explorer(ADX)에서 **꼭 알아야 할 핵심만** AWS 서비스와의 대응 관계 중심으로 정리한다.

## 한 줄 요약

ADX는 **대량의 로그·시계열·텔레메트리 데이터를 준실시간으로 수집·저장·쿼리하는 완전관리형 분석 데이터베이스**다. AWS로 비유하면 **"OpenSearch/Redshift 같은 컬럼형 분석 클러스터 + Athena식 저장소 즉시 쿼리"를 하나로 합치고, 쿼리는 KQL로 하는 서비스**다.

## AWS ↔ Azure/ADX 대응

| AWS | Azure / ADX | 메모 |
| --- | --- | --- |
| Amazon Athena (S3 즉시 쿼리) | **ADX External Table** (Blob/ADLS 즉시 쿼리) | 데이터를 옮기지 않고 그 자리에서 쿼리 |
| Amazon Redshift / OpenSearch (컬럼형·로그 분석) | **ADX 네이티브 테이블**(ingest한 데이터) | 인덱싱·hot cache로 초고속 |
| Amazon Timestream (시계열) | **ADX 시계열 함수** | 이상탐지·예측 내장 |
| Amazon S3 | **Azure Blob Storage / ADLS Gen2** | 객체 저장소 |
| AWS Glue Data Catalog | External Table 정의에 내장(**별도 카탈로그 없음**) | 스키마·경로·파티션을 테이블 정의에 포함 |
| CloudWatch Logs / Logs Insights | **Azure Monitor / Log Analytics** | 동일한 KQL 사용 |
| Presto/Trino·Redshift SQL | **KQL (Kusto Query Language)** | SQL 아님(단, T-SQL 일부 지원) |
| IAM Role | **Microsoft Entra ID + Managed Identity + Azure RBAC** | |
| Reserved Instances / Savings Plans | **Azure Reservation + Savings Plan** | |
| VPC / Security Group | **VNet / NSG / Private Endpoint** | |

## 꼭 알아야 할 5가지

1. **쿼리 언어는 SQL이 아니라 KQL이다.** 파이프(`|`)로 표를 변형하는 모델로, `where`·`summarize`·`join` 몇 개만 알면 로그 분석은 대부분 된다. SQL 경험자는 "SQL to Kusto cheat sheet"로 빠르게 전환할 수 있고, 일부 T-SQL도 지원한다.
2. **Athena처럼 서버리스가 아니라 "프로비저닝된 클러스터"다.** ADX는 켜져 있는 클러스터에 **분 단위로 과금**된다(쿼리 수와 무관). 대신 hot cache 덕분에 반복 쿼리가 매우 빠르고, 안 쓸 때는 클러스터를 **중지(stop)** 해 과금을 멈출 수 있다.
3. **로그 저장소형(append-only)이라 UPDATE가 없다.** 데이터를 계속 추가하고 조회하는 데 최적화되어 있으며, 잦은 수정·삭제가 필요한 트랜잭션 업무(OLTP)에는 맞지 않는다. 그런 용도는 Azure SQL·Cosmos DB를 쓴다.
4. **저장소 위 즉시 쿼리(External Table)와 빠른 ingested 쿼리를 둘 다 할 수 있다.** 원본을 옮기지 않고 Blob을 바로 쿼리(Athena형)하거나, 자주 쓰는 데이터는 클러스터로 ingest해 인덱싱·캐싱된 초고속 쿼리를 한다. 둘을 섞는 하이브리드가 일반적이다.
5. **권한은 IAM이 아니라 Entra ID + Managed Identity + RBAC로 준다.** 예를 들어 클러스터가 Blob을 읽게 하려면 클러스터의 관리 ID에 Storage RBAC 역할을 부여한다(키·시크릿 없이).

## 언제 ADX가 맞나 (그리고 언제 아닌가)

**맞는 경우**
- 대량 로그·텔레메트리·시계열을 **준실시간**으로 수집해 인터랙티브하게 분석·상관·이상탐지.
- 저장소(Blob)에 쌓인 원본 로그를 **옮기지 않고 즉시 쿼리·조인**(Athena형).
- 여러 사용자가 **자주·동시에** 쿼리하는 관측성/보안 분석 플랫폼.

**맞지 않는 경우**
- 단건 레코드의 빈번한 수정·삭제(트랜잭션) → Azure SQL / Cosmos DB.
- 아주 가끔 한 번씩만 조회하는 소량 데이터 → 클러스터 상시 과금이 비효율. **Log Analytics**나 **Microsoft Fabric(Eventhouse)** 의 소비형 모델을 고려.

## 비용 모델 — Athena와 무엇이 다른가

| 항목 | Amazon Athena | Azure Data Explorer |
| --- | --- | --- |
| 과금 방식 | **서버리스**, 스캔한 데이터량(TB)당 | **프로비저닝 클러스터**(엔진 VM + ADX 마크업)를 **분 단위**로 |
| 인프라 | 없음(요청 시 실행) | 클러스터가 떠 있음(중지 가능) |
| 반복 쿼리 | 매번 스캔 비용 | **hot cache**로 매우 빠름, 쿼리 수 늘수록 유리 |
| 비용 최적화 | 쿼리 최적화·파티셔닝 | 작은 SKU로 시작 → 안 쓸 때 stop, 장기는 예약/Savings Plan |

- 핵심 기대치: **ADX는 "가끔 한 번" 모델이 아니라 "켜 두고 많이 쓰는" 모델**이다. 쓰임이 산발적이면 Athena형 소비 모델(Log Analytics·Fabric)이 더 맞을 수 있다.
- External Table로 조회하면 데이터를 클러스터에 저장하지 않으므로 **별도 저장 비용은 없고**, 클러스터 컴퓨트와 Storage 트랜잭션 비용만 든다.
- 정확한 견적은 지역·SKU·데이터량에 따라 다르므로 Azure Pricing Calculator로 산정한다.

## 바로 해보기

- **KQL 무료 연습:** 공개 `help` 클러스터(`https://dataexplorer.azure.com` → `help` / `Samples` / `StormEvents`)에서 계정만 있으면 바로 쿼리해 볼 수 있다.
- **본격 실습:** External Table·Managed Identity가 필요한 시나리오는 **Dev/Test 이상 전용 클러스터**가 필요하다(무료 클러스터는 External Table 미지원).
- **같은 KQL 재사용:** ADX에서 익힌 KQL은 Azure Monitor·Microsoft Sentinel·Application Insights에서 그대로 쓴다.

## 자주 묻는 질문

**Athena를 그대로 대체하나요?** — 개념(저장소 즉시 쿼리)은 External Table로 대응됩니다. 다만 과금 모델이 서버리스가 아니라 클러스터 기반이라는 점이 가장 큰 차이입니다.

**꼭 KQL을 배워야 하나요?** — 네, 기본은 KQL입니다. SQL 경험이 있으면 대응표로 빠르게 익힐 수 있고 일부 T-SQL도 됩니다.

**실시간인가요?** — 수집·flush 지연(보통 수 분)이 있어 준실시간입니다.

**Glue 같은 카탈로그가 필요한가요?** — 아니요. External Table 정의 자체가 스키마·경로·파티션을 담아 별도 카탈로그가 없습니다.

**Private 네트워크에서 되나요?** — Private Endpoint(인바운드)와 Managed Private Endpoint(아웃바운드)로 사설망에서 사용할 수 있습니다.

## 참고 자료

- Microsoft Learn — What is Azure Data Explorer?: https://learn.microsoft.com/azure/data-explorer/data-explorer-overview
- Microsoft Learn — External tables (query-in-place): https://learn.microsoft.com/kusto/query/schema-entities/external-tables
- Microsoft Learn — SQL to Kusto (KQL) cheat sheet: https://learn.microsoft.com/kusto/query/sqlcheatsheet
- Microsoft Learn — Azure Data Explorer pricing: https://learn.microsoft.com/azure/data-explorer/pricing-overview
- Microsoft Learn — Free Azure Data Explorer cluster: https://learn.microsoft.com/azure/data-explorer/start-for-free