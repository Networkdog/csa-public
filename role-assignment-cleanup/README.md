# Azure Role Assignment 조건부 일괄 삭제 및 롤백

[remove-roleassignments.py](remove-roleassignments.py)는 Azure 리소스의 직접 RBAC 할당과 선택한 Azure resource PIM 할당을 조회, 삭제, 복원합니다. Python 3.9 이상 표준 라이브러리와 Azure CLI의 기존 로그인만 사용합니다. `pip install`, Azure SDK, `resource-graph` CLI 확장은 필요하지 않습니다.

**기본 실행은 Dry run이며 일반 영구 RBAC만 선택합니다.** 실제 변경은 `--apply`가 필요합니다. `--yes`만으로 삭제가 활성화되지 않습니다.

## 빠른 시작

Azure Cloud Shell Bash에서 다음 순서로 실행합니다. 예시의 구독 ID와 RG 이름은 실제 대상에 맞게 지정합니다. `~/clouddrive`는 영구 저장소가 연결되어 있어야 합니다.

```bash
python3 remove-roleassignments.py --help
python3 remove-roleassignments.py delete --help

python3 remove-roleassignments.py delete \
  --subscription "00000000-0000-0000-0000-000000000000" \
  --resource-group "rg-example" \
  --description-contains "cleanup-ticket-123" \
  --dry-run
```

일치 수, 보호된 항목, 표시된 표본 및 출력된 JSONL 파일의 전체 목록을 검토한 뒤 실행합니다.

```bash
python3 remove-roleassignments.py delete \
  --subscription "00000000-0000-0000-0000-000000000000" \
  --resource-group "rg-example" \
  --description-contains "cleanup-ticket-123" \
  --rollback-file "$HOME/clouddrive/rbac-delete-ticket123.jsonl" \
  --apply
```

터미널에서 `DELETE <건수>`를 입력해야 합니다. 검토가 끝난 자동화에서는 `--apply --yes`를 사용합니다. 기존 롤백 파일은 덮어쓰지 않으므로 새 실행에는 새 파일명을 지정하거나 기본 자동 파일명을 사용합니다.

```bash
python3 remove-roleassignments.py rollback \
  --rollback-file "$HOME/clouddrive/rbac-delete-ticket123.jsonl" \
  --dry-run

python3 remove-roleassignments.py rollback \
  --rollback-file "$HOME/clouddrive/rbac-delete-ticket123.jsonl" \
  --apply
```

복원 확인 문구는 `RESTORE <건수>`입니다. **삭제 Dry run에서 만든 preview 파일은 복원에 사용할 수 없습니다.**

## 범위 지정

범위 root는 필수이며 다음 중 하나를 선택합니다. 범위를 생략해 테넌트 전체로 확장하지 않습니다.

| 옵션 | 포함 범위 |
| --- | --- |
| `--management-group MG_ID` | MG 자체, 모든 자식 MG 및 소속 구독 아래의 직접 할당 |
| `--subscription SUBSCRIPTION_ID` | 구독 자체 및 모든 하위 범위 |
| `--subscription ID --resource-group RG_NAME` | 해당 RG 자체 및 모든 하위 범위 |
| `--resource-id ARM_ID` | 정확히 해당 리소스에 직접 부여된 할당 |
| `--resource-id ARM_ID --include-resource-descendants` | 해당 리소스와 자식 리소스의 직접 할당 |

지정 범위보다 상위에서 상속된 할당과 형제 범위는 제외합니다. 예를 들어 `rg-a`는 `rg-ab`와 일치하지 않습니다. MG 계층은 실제 descendants API로 확인하며 이름 접두사로 추측하지 않습니다. Management Group에는 표시 이름이 아닌 ID를 입력합니다.

MG 조회가 ARG의 10,000개 구독 한도를 초과하면 부분 목록으로 삭제하지 않고 중단합니다. 더 작은 명시적 범위로 실행해야 합니다.

## 조건

서로 다른 조건은 **AND**, 같은 옵션을 여러 번 지정하면 그 값들은 **OR**입니다. 빈 문자열은 허용하지 않습니다. ID, 이름, 이메일 및 키워드는 대소문자를 구분하지 않습니다.

| 옵션 | 비교 |
| --- | --- |
| `--description-contains TEXT` | Role Assignment의 실제 Description 부분 일치 |
| `--principal-id OBJECT_ID` | 할당 대상의 Entra Object ID. Application/Client ID가 아님 |
| `--principal-type TYPE` | `User`, `Group`, `ServicePrincipal`, `ManagedIdentity`, `ForeignGroup`, `Device`, `AgentUser`, `AgentServicePrincipal` |
| `--principal-name NAME` | `displayName` 정확 일치 |
| `--principal-name-contains TEXT` | `displayName` 부분 일치 |
| `--principal-email ADDRESS` | User의 `mail` 또는 `userPrincipalName`, Group의 `mail` 정확 일치 |
| `--assignment-kind KIND` | 아래 유형 선택. 기본값 `regular`, 반복 지정 가능 |
| `--expiration any\|permanent\|time-bound` | 유효기간 조건. 기본값 `any` |

```bash
python3 remove-roleassignments.py delete \
  --management-group "mg-platform" \
  --principal-type User \
  --principal-email "user1@example.com" \
  --principal-email "user2@example.com" \
  --description-contains "temporary" \
  --dry-run

python3 remove-roleassignments.py delete \
  --subscription "00000000-0000-0000-0000-000000000000" \
  --resource-group "rg-example" \
  --principal-type ManagedIdentity \
  --principal-name "mi-example" \
  --dry-run
```

ARM에서는 Managed Identity도 `principalType=ServicePrincipal`입니다. 스크립트는 Microsoft Graph의 `servicePrincipalType`을 확인해 구분합니다. 이 CLI에서 `ServicePrincipal`은 MI가 아닌 Application/Legacy 서비스 주체를 뜻합니다. 둘 다 선택하려면 두 옵션을 반복합니다. 원본 ARM principalType은 백업/복원 시 보존합니다.

동일 이름의 주체가 여럿이면 모든 일치 Object ID를 대상으로 합니다. 이름이 고유하다고 가정하지 않습니다. 이름/이메일/MI 구분에 필요한 Graph 읽기가 실패하면 조건을 무시하지 않고 중단합니다. SP의 알림 이메일이나 소유자 이메일은 이메일 조건으로 사용하지 않습니다. 그룹의 직접 할당은 지원하지만 그룹 멤버십을 펼치거나 변경하지 않습니다.

## PIM

| `--assignment-kind` | 의미 | 삭제/복원 경로 |
| --- | --- | --- |
| `regular` | 현재의 영구 Active Assigned RBAC | 일반 ARM DELETE/PUT. 실제 PIM 관리 스케줄이면 PIM 요청 API |
| `pim-eligible` | 미만료 Eligible 스케줄. 미래 시작 포함 | Eligibility `AdminRemove` / `AdminAssign` |
| `pim-timebound` | 관리자가 부여한 기간제 Assigned 스케줄. 미래 시작 포함 | Assignment `AdminRemove` / `AdminAssign` |
| `pim-activated` | Eligible에서 활성화된 인스턴스 | Assignment `AdminRemove`; 복원은 사용자 재활성화 필요 |

```bash
python3 remove-roleassignments.py delete \
  --subscription "00000000-0000-0000-0000-000000000000" \
  --resource-group "rg-example" \
  --assignment-kind pim-eligible \
  --expiration time-bound \
  --principal-id "11111111-1111-1111-1111-111111111111" \
  --dry-run
```

- PIM은 ARG에 스케줄이 없으므로 ARM PIM API로 보완합니다. 기본 `regular` 실행도 기간제·활성화 할당을 배제하기 위해 PIM 읽기를 수행합니다. PIM 조회 403을 'PIM 없음'으로 취급하지 않습니다.
- PIM API에는 Entra ID P2 또는 ID Governance 라이선스가 필요합니다. `AadPremiumLicenseRequired`가 발생해도 자동으로 검사를 생략하지 않습니다. PIM이 전혀 없음을 별도로 확인한 범위(예: 방금 만든 격리 테스트 RG)에서만 `--assume-no-pim`으로 명시적으로 검사를 생략할 수 있습니다. 이 옵션은 `regular`에만 허용되고 경고 및 저널에 기록됩니다. 라이선스 부족 자체가 기존 PIM 할당이 없다는 증거는 아니며, PIM이 있을 가능성이 있는 범위에서는 사용하면 안 됩니다.
- 일반 영구 RBAC가 PIM 결과에도 표시될 수 있습니다. `originRoleAssignmentId`, 스케줄 요청 연결, 종류 및 만료를 검증해 실제 제어 경로를 구분합니다. 모호하거나 생성/삭제 중인 상태는 안전을 위해 중단합니다.
- `pim-eligible`와 `pim-timebound` 복원은 원래 scope/주체/역할/조건을 유지하고 **원래 절대 종료 시각을 연장하지 않습니다**. 이미 만료됐거나 남은 기간이 5분 미만이면 재부여하지 않습니다. 현행 PIM 정책, 승인, 최소 유지 기간 때문에 요청이 거절될 수 있습니다.
- `pim-activated`는 관리자 `AdminAssign`이나 일반 영구 RBAC로 대체 복원하지 않습니다. 당사자의 재활성화, MFA, 승인이 필요할 수 있습니다. 실제 삭제에는 `--allow-nonrestorable-pim`을 추가로 요구합니다.
- PIM API가 지원하지 않는 backing RBAC Description/위임 필드가 있는 경우에도 이 위험 동의 옵션을 요구합니다. 파일에는 원본을 남기지만 해당 필드의 자동 재적용을 보장하지 않습니다.
- PIM 객체에 Description이 없으면 Description 조건에 일치하지 않습니다. `justification`을 Description으로 간주하지 않습니다.
- Eligible에 연결된 활성화가 삭제 대상으로 확인되지 않았으면 Eligible 삭제를 차단합니다. 필터 밖의 활성화를 자동 삭제하지 않습니다. 연결된 활성화를 먼저 제거하고 Eligible을 제거하며, 복원 시에는 Eligible이 먼저입니다.
- 원래 PIM 스케줄 ID, 생성자, 생성 시각, 승인·활성화 이력은 복원되지 않습니다. `201 Created`만으로 완료라 판단하지 않고 요청 상태와 실제 리소스를 재조회합니다.

## 조회 및 진행 표시

기본 `--source arg`는 자동 생성한 `AuthorizationResources` KQL과 REST API를 사용합니다. 직접 KQL 문자열/파일 입력은 제공하지 않습니다. ID 정렬, continuation token, 중복 및 잘림 검사를 수행하고 전체 목록을 수집한 후에만 삭제합니다.

ARG에는 색인 지연과 PII 제거가 있으므로 Description을 포함한 최종 조건과 백업은 ARM 원본으로 검증합니다. 따라서 Description 조건만 좁힐 때도 먼저 넓은 범위의 live 조회가 필요할 수 있습니다. 아직 ARG에 색인되지 않은 새 할당까지 필요한 경우 `--source arm`을 사용합니다. ARG를 재조회하며 삭제 대상을 계속 늘리지 않습니다.

`--read-workers 4`가 기본이며 읽기만 최대 4개를 병렬 처리합니다. 허용 범위는 1~16입니다. 삭제/복원 쓰기는 직렬입니다. `--timeout`은 HTTP/CLI 요청 제한(기본 60초), `--poll-timeout`은 완료 확인 제한(기본 300초)입니다.

기본 출력은 테넌트/범위/모드, 단계별 처리 수, 처음 10개 표본, 보호 수, 저널 경로와 최종 결과입니다. 전체 일치 목록은 저널의 `snapshot`에 있습니다. `--verbose`는 생성 KQL과 상세 진행을 표시합니다. 토큰과 인증 JSON은 출력/저장하지 않습니다.

## 롤백 파일과 안전장치

JSONL 저널에 전체 원본 스냅샷을 먼저 저장하고 `flush`/`fsync`한 뒤, 각 작업의 `delete_intent`, `delete_success` 등을 기록합니다. 파일을 만들거나 내구성 있게 기록할 수 없으면 새 Azure 변경을 멈춥니다. 기본 파일명은 실행 시각과 무작위 ID를 포함합니다.

- 실제 삭제 성공 항목만 자동 복원합니다. 미시도, 보호, 원래 없던 항목은 복원하지 않습니다.
- 네트워크 오류나 강제 종료로 결과가 불확정이면 기본 복원에서 제외합니다. 파일과 실제 상태를 검토한 뒤 `rollback --reconcile-pending --dry-run`으로 확인하고, 명시적으로 `--apply`할 수 있습니다. '현재 없음'만으로 원래 삭제 원인을 증명할 수 없다는 점에 유의합니다.
- 반복 복원은 이미 완료한 항목을 다시 생성하지 않습니다. 복원 후 다른 관리자가 의도적으로 제거한 권한을 해당 저널로 계속 재부여하지 않습니다.
- 기존 동일 ID의 내용이 다르거나 다른 ID로 같은 권한이 있으면 덮어쓰지 않습니다. 사용자·역할 정의·리소스 자체를 재생성하지 않습니다.
- 저널의 tenant/cloud 및 scope와 현재 계정을 대조합니다. 저널에 들어 있는 임의 URL이나 명령은 실행하지 않습니다.
- 실행 중에는 저널에 배타적 잠금을 유지합니다. 마지막 불완전한 줄은 성공으로 간주하지 않습니다. 중간 기록 손상이나 알 수 없는 형식은 복원을 거부합니다.
- 호출자에게 직접 할당된 권한은 기본 보호합니다. `--allow-self-removal`은 이 보호를 해제하지만, 별도 복구 운영자의 권한을 반드시 유지해야 합니다. 그룹 경유 권한이나 모든 권한 상실 경로를 자동 검증하는 기능은 아닙니다.
- `--tenant-id`는 현재 테넌트가 맞는지 확인하는 가드이며 계정/테넌트를 전환하지 않습니다. Cloud Shell에서 지원되지 않는 token 명령의 `--tenant`도 사용하지 않습니다.

Cloud Shell에서는 마운트된 `~/clouddrive`를 기본 저장 위치로 사용합니다. 저장소 없는 임시 세션이나 그 밖의 위치는 세션 종료 시 파일이 유실될 수 있어 실제 실행을 기본 차단합니다. 이를 의도적으로 허용하려면 `--rollback-file PATH --allow-ephemeral-backup`을 함께 지정해야 합니다. 로컬 PC에서는 기본 현재 폴더에 생성합니다.

저널에는 Object ID, 이름, 이메일 및 역할 정보가 포함될 수 있습니다. 암호화된 비밀 저장소가 아니며 신뢰할 수 있는 저장소에 보관해야 합니다. POSIX 파일 권한 0600만으로 Azure File Share의 전체 보안이 보장되지는 않습니다. 자동 롤백은 전체 작업의 원자적 트랜잭션 복원이 아니며, 다른 관리자의 동시 변경과 API 호출 사이의 경합도 완전히 제거할 수 없습니다.

## 필요한 권한

조회 범위의 RBAC/역할 정의와 필요한 PIM schedules/instances 읽기, MG 선택 시 관리 그룹 계층 읽기가 필요합니다. 삭제에는 `Microsoft.Authorization/roleAssignments/delete`, 일반 복원에는 `Microsoft.Authorization/roleAssignments/write`, PIM 변경에는 해당 `roleAssignmentScheduleRequests/write` 또는 `roleEligibilityScheduleRequests/write` 권한이 필요합니다. 실제 허용 여부는 deny assignment, ABAC 조건 및 PIM 정책에 따라 달라집니다.

이름/이메일/MI 구분에는 별도의 Microsoft Graph 읽기 권한이 필요합니다. 예를 들어 다른 사용자의 기본 프로필에는 `User.ReadBasic.All` 등 해당 API에서 허용하는 권한, 서비스 주체에는 `Application.Read.All` 또는 동등한 기존 권한, 그룹에는 기본 그룹 정보 읽기 권한이 필요합니다. **Azure RBAC Owner만으로 Graph 읽기가 보장되지는 않습니다.** 스크립트는 앱 등록, 관리자 동의, 로그인, 권한 상승을 자동 수행하지 않습니다.

Entra directory roles, PIM for Groups 멤버십, 앱 역할 할당, deny assignments 및 classic administrators는 이 스크립트의 삭제 대상이 아닙니다. 삭제/복원이 성공해도 캐시된 애플리케이션 권한과 기존 세션에 즉시 반영된다고 보장하지 않습니다.

## 종료 코드 및 검증

| 코드 | 의미 |
| --- | --- |
| `0` | 검증/작업 완료 또는 변경할 항목 없음 |
| `1` | 오류, 실제 실행에서 보호된 항목 존재, 불확정 결과 또는 수동/부분 복원 필요 |
| `2` | CLI 인자 오류 |
| `130` | 사용자 취소/중단 |

두 파일만 공개한 배포본에는 개발용 테스트 파일이 포함되지 않습니다. 공개 배포본에서는 다음 명령으로 CLI 도움말을 확인할 수 있습니다. 이 명령은 Azure에 접속하거나 리소스를 변경하지 않습니다.

```bash
python3 remove-roleassignments.py --help
```

테스트 파일이 포함된 개발 작업 폴더에서는 아래 명령으로 추가 모듈 없이 모의 테스트를 실행합니다. 모의 테스트는 실제 Azure 계정을 사용하거나 리소스를 변경하지 않습니다.

```bash
python3 -B -m unittest discover -s tests -p test_remove_roleassignments.py -v
```

주요 검증은 범위 경계, 1,001건 페이지 조회, 조건 조합, MI 구분, PIM 기본 제외, Dry run의 쓰기 0건, 백업 실패/중단, 충돌, 만료 보존, PIM API 경로, 삭제 후 복원 및 재실행입니다. 운영 적용 전에는 격리된 테스트 범위에서 PIM 하위 범위 조회의 완전성, 정책과 권한, Cloud Shell 저장소를 함께 확인해야 합니다.

### 실계정 검증 기록 (2026-09-28)

사용자 승인하에 새 전용 RG와 UAMI, 미연결 NSG, 피어링 없는 VNet/Subnet을 만들고 Reader 테스트 할당 5개를 생성했습니다. 기존 리소스나 기존 역할 할당은 변경하지 않았습니다.

| 검증 | 결과 |
| --- | --- |
| ARG/ARM + MI 유형/이름/Description Dry run | 두 경로 모두 동일한 3개 선택 |
| 사용자 이름 + 이메일 | 1개 일치, 자기 권한 보호 확인 |
| VNet 정확 범위 / 자식 포함 | 각각 0개 / Subnet 할당 1개 선택 |
| 실제 삭제 | 테스트 MI 할당 3개 삭제, 나머지 테스트 할당 2개 유지 |
| 롤백 Dry run / 실제 복원 | 3개 복원 예정 / 원래 ID와 Description 등 속성으로 3개 복원 |
| 롤백 재실행 | 3개 모두 이전 복원 완료로 처리, 중복 생성 없음 |
| 기존 상속 할당 | 93개 전체의 정렬된 원본 JSON 해시가 삭제·복원 전후 동일 |
| 정리 | 새 RG 삭제 확인, 이번 테스트 할당 5개 모두 부재 확인 |

실계정 검증 중 ARM 목록에 테넌트 루트(`/`)의 상속 할당이 포함되는 경우를 확인해 제외 처리를 보완했습니다.

해당 테넌트의 PIM API는 `AadPremiumLicenseRequired`를 반환했습니다. 따라서 PIM을 만들지 않은 새 테스트 범위에서만 `--assume-no-pim`을 명시해 일반 RBAC를 검증했습니다. **PIM 실제 삭제·복원은 라이선스 제약으로 미검증**이며, PIM 경로는 모의 테스트로 검증했습니다. 라이선스나 기존 테넌트 설정은 변경하지 않았습니다.

실계정 실행 환경은 Windows의 Python 3.14와 기존 Azure CLI 로그인입니다. Python 3.9 문법과 표준 라이브러리만 사용하는 조건은 정적으로 검증했으며, Cloud Shell 세션에서의 직접 실행과 MG 계층 실환경 검증은 별도 확인이 필요합니다. 이번 테스트의 추가 Azure 리소스는 남겨두지 않았습니다.

## 공식 참고 자료

- [Cloud Shell 도구, 인증 및 저장소](https://learn.microsoft.com/en-us/azure/cloud-shell/features)
- [Azure CLI 토큰 명령](https://learn.microsoft.com/en-us/cli/azure/account#az-account-get-access-token)
- [Resource Graph REST API](https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources)
- [ARG 범위 옵션](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language#query-scope)
- [RBAC 생성/복원 필드](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create?view=rest-authorization-2022-04-01)
- [PIM 인스턴스와 원본 할당 연결](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignment-schedule-instances/list-for-scope?view=rest-authorization-2020-10-01)
- [PIM 활성 할당 요청](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignment-schedule-requests/create?view=rest-authorization-2020-10-01)
- [PIM Eligible 할당 요청](https://learn.microsoft.com/en-us/rest/api/authorization/role-eligibility-schedule-requests/create?view=rest-authorization-2020-10-01)
- [PIM 라이선스 요건](https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals#privileged-identity-management)
- [Microsoft Graph 서비스 주체 유형](https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0)