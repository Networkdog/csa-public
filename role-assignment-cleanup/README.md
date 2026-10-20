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

## Usage 모음

아래는 Azure Cloud Shell **Bash** 기준입니다. 스크립트를 먼저 내려받은 다음 공통 변수의 예시 값을 실제 대상에 맞게 바꿉니다. 계정이나 구독을 자동 전환하지 않으므로 현재 로그인한 테넌트에서 접근 가능한 범위를 지정해야 합니다. `--tenant-id`는 로그인 전환이 아닌 테넌트 확인용입니다.

```bash
SCRIPT="$HOME/clouddrive/role-assignment-cleanup/remove-roleassignments.py"
SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"
MANAGEMENT_GROUP_ID="mg-example"
RESOURCE_GROUP="rg-example"
RESOURCE_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/stexample"
USER_OBJECT_ID="11111111-1111-1111-1111-111111111111"
OTHER_USER_OBJECT_ID="22222222-2222-2222-2222-222222222222"
GROUP_OBJECT_ID="33333333-3333-3333-3333-333333333333"
TENANT_ID="44444444-4444-4444-4444-444444444444"
KEYWORD="cleanup-ticket-123"
```

예제 1~18은 Azure 변경 없이 후보를 조회합니다. 예제 19~20 및 아래 Owner 정리 예제에서 `--apply`를 지정한 명령은 실제 변경을 수행하므로 필요한 예제만 개별 실행합니다. Dry run도 Azure 조회 권한이 필요하고 로컬 preview 파일을 생성합니다. PIM이 없는 범위에 대한 명시적 처리 방법은 예제 18에 별도로 설명합니다.

### 1. Management Group 전체 하위의 특정 Description

MG 자체와 자식 MG, 구독, RG, 리소스의 직접 할당을 포함합니다. 해당 MG보다 상위에서 내려온 할당은 제외합니다.

```bash
python3 "$SCRIPT" delete \
  --management-group "$MANAGEMENT_GROUP_ID" \
  --description-contains "$KEYWORD" \
  --dry-run
```

### 2. 구독 전체에서 특정 사용자의 할당

`--principal-id`에는 Entra Object ID를 사용합니다. Application/Client ID가 아닙니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --principal-type User \
  --principal-id "$USER_OBJECT_ID" \
  --dry-run
```

### 3. RG 아래에서 두 키워드 중 하나가 포함된 할당

아래 조건은 `선택한 RG 하위 AND (Description에 temporary 포함 OR legacy 포함)`입니다. 두 키워드를 모두 포함해야 한다는 뜻이 아닙니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --description-contains "temporary" \
  --description-contains "legacy" \
  --dry-run
```

### 4. 정확히 한 리소스에 직접 부여된 할당

예를 들어 Storage Account에 직접 부여한 할당만 조회하며, 상위 RG 및 하위 Container 할당은 제외합니다.

```bash
python3 "$SCRIPT" delete \
  --resource-id "$RESOURCE_ID" \
  --description-contains "$KEYWORD" \
  --dry-run
```

### 5. 리소스와 모든 하위 리소스의 할당

예제 4에 하위 범위 포함 옵션을 명시적으로 추가한 경우입니다.

```bash
python3 "$SCRIPT" delete \
  --resource-id "$RESOURCE_ID" \
  --include-resource-descendants \
  --description-contains "$KEYWORD" \
  --dry-run
```

### 6. 이메일 또는 Guest UPN으로 사용자 선택

첫 명령은 `mail` 또는 UPN이 지정 이메일과 정확히 일치하는 사용자를 선택합니다. 두 번째 명령은 Guest UPN 예제이며, `#EXT#`를 포함한 값을 따옴표로 감쌉니다. 두 명령은 서로 다른 예제입니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-type User \
  --principal-email "user@example.com" \
  --description-contains "$KEYWORD" \
  --dry-run

python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-type User \
  --principal-email "guest_example.com#EXT#@tenant.onmicrosoft.com" \
  --dry-run
```

### 7. 사용자 이름 정확 일치 또는 부분 일치

첫 명령은 표시 이름이 정확히 `Example User`인 사용자, 두 번째 명령은 표시 이름에 `Contractor`가 포함된 사용자를 선택합니다. 동명이인이 있으면 모두 일치하므로 결과의 Object ID를 확인해야 합니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-type User --principal-name "Example User" \
  --dry-run

python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-type User --principal-name-contains "Contractor" \
  --description-contains "$KEYWORD" \
  --dry-run
```

### 8. 여러 사용자와 Description을 함께 제한

`(사용자 A OR 사용자 B) AND Description 키워드`로 해석합니다. 서로 다른 필터인 이름과 이메일을 함께 지정하면 두 조건을 모두 만족해야 합니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-type User \
  --principal-id "$USER_OBJECT_ID" \
  --principal-id "$OTHER_USER_OBJECT_ID" \
  --description-contains "$KEYWORD" \
  --dry-run
```

### 9. 그룹에 직접 부여된 할당

그룹 자체의 RBAC 할당을 선택합니다. 그룹 멤버를 제거하거나 사용자별 간접 권한을 별도 할당으로 펼치지 않습니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-type Group \
  --principal-id "$GROUP_OBJECT_ID" \
  --description-contains "$KEYWORD" \
  --dry-run
```

### 10. 일반 Service Principal만 선택

이 CLI의 `ServicePrincipal`은 Managed Identity를 제외합니다. 표시 이름에 `legacy-app`이 포함된 Application/Legacy 서비스 주체만 선택합니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-type ServicePrincipal \
  --principal-name-contains "legacy-app" \
  --dry-run
```

### 11. 특정 Managed Identity만 선택

System-assigned와 User-assigned MI를 모두 유형으로 인식합니다. 두 하위 유형을 나누는 옵션은 없으므로 특정 MI는 Object ID 또는 이름으로 제한합니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-type ManagedIdentity \
  --principal-name "mi-example" \
  --description-contains "$KEYWORD" \
  --dry-run
```

### 12. Service Principal과 Managed Identity를 함께 선택

`User`, `Group`은 제외하고 두 주체 유형만 선택합니다. MI 구분을 위한 Microsoft Graph 읽기 권한이 필요합니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-type ServicePrincipal \
  --principal-type ManagedIdentity \
  --description-contains "$KEYWORD" \
  --dry-run
```

### 13. PIM Eligible의 영구 또는 기간제 할당

첫 명령은 영구 Eligible, 두 번째 명령은 만료 시각이 있는 Eligible만 선택합니다. Eligible에는 실제 Role Assignment Description이 없을 수 있으므로 이 예제는 Object ID로 제한합니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-id "$USER_OBJECT_ID" \
  --assignment-kind pim-eligible --expiration permanent \
  --dry-run

python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-id "$USER_OBJECT_ID" \
  --assignment-kind pim-eligible --expiration time-bound \
  --dry-run
```

### 14. 관리자가 부여한 기간제 Active 할당

Eligible에서 활성화한 권한과는 다른 `Assigned` 기간제 유형입니다. 복원해도 원래 종료 시각이 연장되지 않습니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-id "$USER_OBJECT_ID" \
  --assignment-kind pim-timebound \
  --dry-run
```

### 15. 현재 PIM 활성화 할당 확인

자동 원상복구가 불가능할 수 있어 기본적으로 보호된 항목으로 표시됩니다. 아래 명령은 조회만 합니다. 실제 삭제를 의도할 때는 `--allow-nonrestorable-pim`과 `--apply`가 모두 필요하며, 당사자의 재활성화/MFA/승인이 필요한 위험을 먼저 검토해야 합니다. `--yes`는 이 보호를 해제하지 않습니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-id "$USER_OBJECT_ID" \
  --assignment-kind pim-activated \
  --dry-run
```

### 16. 일반 RBAC와 선택한 PIM 유형을 함께 확인

활성화 유형은 제외한 예제입니다. PIM 유형을 지정하면 기본 `regular`가 자동으로 추가되지 않으므로 포함할 유형을 모두 나열합니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-id "$USER_OBJECT_ID" \
  --assignment-kind regular \
  --assignment-kind pim-eligible \
  --assignment-kind pim-timebound \
  --dry-run
```

### 17. 최신 ARM 조회, 상세 출력 및 테넌트 확인

ARG 색인 지연을 피해야 할 때 `--source arm`을 사용합니다. `--read-workers`는 읽기 병렬도이며 쓰기를 병렬화하지 않습니다. 기본 ARG 조회에서 생성 KQL을 보려면 `--source arg --verbose`를 사용합니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --description-contains "$KEYWORD" \
  --tenant-id "$TENANT_ID" \
  --source arm --read-workers 8 --timeout 90 \
  --verbose --dry-run
```

### 18. PIM이 없음을 별도로 확인한 범위

라이선스 오류만 보고 이 옵션을 추가하면 안 됩니다. 운영자가 해당 범위에 PIM이 없음을 별도로 확인했을 때만 사용합니다. 이 모드에서는 PIM 제외 여부를 API로 검증하지 않으며, 해당 사실이 경고와 저널에 기록됩니다. PIM 유형 옵션과 함께 사용할 수 없습니다.

```bash
python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-id "$USER_OBJECT_ID" \
  --description-contains "$KEYWORD" \
  --assignment-kind regular --assume-no-pim \
  --dry-run
```

### 19. 검토 후 실제 삭제 또는 자동화 실행

먼저 같은 범위·조건으로 Dry run을 검토합니다. 아래의 두 실행 방식 중 **하나만** 선택합니다. 첫 명령은 `DELETE <건수>` 입력을 요구하고, 두 번째 명령은 이미 별도 승인을 받은 자동화용입니다. 동일한 롤백 파일은 덮어쓰지 않습니다. 새 실행에는 새 파일명을 사용합니다.

영구 저장소가 마운트된 `~/clouddrive`에 기록합니다. 단순히 같은 이름의 디렉터리를 만드는 것으로 영구 저장소 연결을 대신할 수 없습니다. 삭제 후 복구할 별도 운영자의 권한을 유지해야 합니다.

```bash
ROLLBACK_FILE="$HOME/clouddrive/rbac-cleanup-$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}.jsonl"

python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-id "$USER_OBJECT_ID" \
  --description-contains "$KEYWORD" \
  --rollback-file "$ROLLBACK_FILE" \
  --apply
```

```bash
ROLLBACK_FILE="$HOME/clouddrive/rbac-cleanup-$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}.jsonl"

python3 "$SCRIPT" delete \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --principal-id "$USER_OBJECT_ID" \
  --description-contains "$KEYWORD" \
  --rollback-file "$ROLLBACK_FILE" \
  --apply --yes
```

현재 로그인한 사용자 자신의 할당은 이 명령에서도 기본 보호됩니다. `--allow-self-removal`은 독립적인 복구 수단을 확보한 뒤 의도적으로 자기 할당을 제거할 때만 사용합니다. `--yes`는 자기 권한, PIM 복원 제약 및 백업 안전 검사를 우회하지 않습니다.

### 20. 복원 미리보기, 실제 복원 및 중단된 실행 복구

`ROLLBACK_FILE`은 예제 19에서 실제 삭제할 때 생성한 파일 경로입니다. 다른 세션에서는 그 실제 경로로 변수를 다시 지정해야 합니다. preview 파일이 아닙니다.

```bash
python3 "$SCRIPT" rollback \
  --rollback-file "$ROLLBACK_FILE" \
  --dry-run
```

복원 대상을 검토한 뒤 실제 복원을 실행합니다. `RESTORE <건수>` 확인을 요청합니다.

```bash
python3 "$SCRIPT" rollback \
  --rollback-file "$ROLLBACK_FILE" \
  --apply
```

네트워크 오류나 강제 종료 후 불확정 항목이 있으면 다음 명령으로 재확인합니다. 이는 확인용 예제이며, 실제 복원은 결과와 삭제 원인을 검토한 뒤 별도로 승인해야 합니다. '지금 없음'만으로 이 스크립트가 삭제했다는 사실이 증명되지는 않습니다.

```bash
python3 "$SCRIPT" rollback \
  --rollback-file "$ROLLBACK_FILE" \
  --reconcile-pending --dry-run
```

### 조건 작성 시 주의

- `--description-contains "*temporary*"`의 `*`는 와일드카드가 아니라 문자 자체입니다. 부분 일치는 `--description-contains "temporary"`로 지정합니다.
- 같은 키워드 옵션을 반복하면 OR입니다. Description에 두 키워드가 모두 있어야 하는 AND 조건이나 정규식 조건은 현재 제공하지 않습니다.
- 범위 root는 한 번에 하나만 지정합니다. 여러 구독을 처리할 때는 각각 별도로 Dry run하고 실행별로 다른 롤백 파일을 사용합니다.
- `--expiration time-bound`만 지정하면 기본 유형이 `regular`라 원하는 기간제 PIM 목록을 찾지 못합니다. `--assignment-kind pim-timebound` 또는 `pim-eligible`을 함께 지정합니다.
- `--role-id`에는 Role Assignment ID가 아닌 역할 정의 GUID를 사용합니다. `--role-name`, `--query`, `--kql-file`은 현재 지원하지 않습니다.
- `-dev-`처럼 `-`로 시작하는 필터 값은 `--subscription-name-contains=-dev-`처럼 `=`로 연결합니다.
- 위 예제의 옵션과 조합은 로컬 CLI 파서로 검증합니다. PIM 실제 처리, MG 계층 및 Cloud Shell 실행의 실환경 검증 한계는 아래 검증 기록을 참고합니다.

## dev/stg 구독의 Owner만 정리

다음은 선택한 MG 하위에서 구독 Display Name에 **`-dev-` 또는 `-stg-`가 포함된 구독**만 대상으로, 기본 제공 **Owner** 역할의 일반 영구 Active 할당을 선택하는 예제입니다. 대소문자를 구분하지 않습니다. MG 자체와 자식 MG에 직접 부여한 할당, 상위 MG에서 상속된 할당 및 다른 이름의 구독은 제외합니다. 일치 구독의 RG·리소스에 직접 부여한 Owner도 범위에 포함됩니다.

Owner 역할 정의 GUID는 `8e3af657-a8ff-443c-a75c-2fe8c4bcb635`입니다. 주체 조건을 추가하지 않으면 사용자뿐 아니라 그룹·서비스 주체 등 모든 주체의 일치 Owner 할당을 선택하되, 실행자 본인 할당은 기본 보호합니다.

먼저 아래 명령으로 조회합니다. `MANAGEMENT_GROUP_ID`는 위 공통 변수의 값을 실제 MG ID로 바꿔 사용합니다.

```bash
python3 "$SCRIPT" delete \
  --management-group "$MANAGEMENT_GROUP_ID" \
  --subscription-name-contains=-dev- \
  --subscription-name-contains=-stg- \
  --role-id "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" \
  --assignment-kind regular \
  --use-pim-for-owner-removal \
  --source arm \
  --dry-run
```

`--use-pim-for-owner-removal`은 **삭제 대상 Owner를 Eligible로 변환하지 않습니다.** 실행자에게 각 대상 구독에 이미 직접 부여된 Eligible Owner 또는 User Access Administrator를 임시 활성화하는 옵션입니다. 새 Eligible/영구 권한은 만들지 않으며, 권한이 없으면 삭제 전에 중단합니다. 자세한 전제와 정리 방법은 아래 PIM 절을 확인합니다.

Dry run의 구독 ID·표시 이름, 삭제 목록, 보호 목록 및 PIM 활성화 계획을 검토하고, 독립적인 복구 운영자를 확보한 뒤 실제 실행합니다.

```bash
ROLLBACK_FILE="$HOME/clouddrive/rbac-owner-devstg-$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}.jsonl"

python3 "$SCRIPT" delete \
  --management-group "$MANAGEMENT_GROUP_ID" \
  --subscription-name-contains=-dev- \
  --subscription-name-contains=-stg- \
  --role-id "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" \
  --assignment-kind regular \
  --use-pim-for-owner-removal \
  --source arm \
  --rollback-file "$ROLLBACK_FILE" \
  --apply
```

`DELETE <건수>` 확인을 요구합니다. 승인된 자동화에서만 `--yes`를 추가합니다. 본인 Owner까지 의도적으로 제거하려면 `--allow-self-removal`이 별도로 필요합니다. 이 경우에도 활성화에 사용하는 원본 Eligible/동일 scope의 동일 실행자 역할은 삭제 집합에 포함될 수 없습니다.

특정 사용자의 Owner만 제거하려면 두 명령에 동일한 `--principal-id "$USER_OBJECT_ID"` 조건을 추가합니다. Eligible·기간제·활성화 Owner까지 선택하려면 원하는 `--assignment-kind`를 명시해야 하며, 기존 PIM 보호 및 복원 제약도 그대로 적용됩니다.

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

### 구독 표시 이름 필터

`--subscription-name-contains TEXT`를 반복하면 값들은 OR로 해석합니다. 다른 범위·역할·주체 조건과는 AND입니다. 구독의 ARM `displayName`을 조회하며, 사용자/그룹의 `displayName`이나 구독 ID를 이름으로 간주하지 않습니다.

- `--management-group`과 함께 쓰면 실제 하위 구독 중 일치하는 구독만 포함하고 **모든 MG scope의 할당을 제외**합니다. MG 할당을 삭제하면 일치하지 않는 구독에도 영향을 줄 수 있기 때문입니다.
- `--subscription`, `--resource-group`, `--resource-id`에서도 해당 구독 이름을 추가로 검사하며, 기존 RG/리소스 경계는 유지합니다.
- 이름 조회 실패·누락·테넌트 불일치는 조건을 무시하지 않고 중단합니다. 일치 구독이 없으면 RBAC/PIM 인벤토리 조회나 Azure 변경 없이 종료합니다.
- 실제 실행 전에는 범위·구독 이름을 다시 확인하고, 각 삭제와 임시 PIM 활성화 전에도 이름을 확인합니다. 확인한 이름이 바뀌면 중단합니다. 이미 만든 임시 PIM 권한의 정리는 이름 변경 여부와 관계없이 원래 구독 ID에서 수행합니다.
- 롤백은 기록된 구독 ID와 원래 삭제 목록을 사용합니다. 삭제 후 이름이 바뀌어도 원래 권한을 복원할 수 있으며, 다른 구독으로 복원 대상을 확장하지 않습니다.

## 조건

서로 다른 조건은 **AND**, 같은 옵션을 여러 번 지정하면 그 값들은 **OR**입니다. 빈 문자열은 허용하지 않습니다. ID, 이름, 이메일 및 키워드는 대소문자를 구분하지 않습니다.

| 옵션 | 비교 |
| --- | --- |
| `--subscription-name-contains TEXT` | 선택 범위 안의 구독 Display Name 부분 일치. 반복하면 OR |
| `--role-id GUID` | 역할 정의 GUID 일치. 반복하면 OR. 기본 제공 Owner는 `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` |
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

### 마지막 구독 Owner 삭제를 위한 임시 활성화

`--use-pim-for-owner-removal`은 삭제 가능한 **구독 scope의 기본 제공 Owner**가 있을 때 실행자의 기존 PIM 권한을 사용합니다. RG/리소스/MG의 Owner에 대해 별도의 구독 활성화를 자동 생성하는 기능은 아닙니다.

1. 최초 조회·백업에 필요한 기존 읽기 권한과, 각 대상 구독에 실행자 **사용자 본인에게 직접** 부여된 유효한 Eligible Owner 또는 User Access Administrator가 필요합니다. 조건부, 그룹/상속 경유 및 미래 시작 Eligible은 자동 활성화하지 않습니다. 사용 가능한 후보 중 기존 활성화를 먼저 재사용하고, 새 활성화가 필요하면 User Access Administrator를 우선합니다.
2. Dry run에서는 계획과 원본 Eligible ID만 확인합니다. 실제 실행은 완전한 백업과 사용자 확인을 마친 뒤 `SelfActivate`를 요청하며, PIM 스케줄·인스턴스·실제 backing RBAC가 일치하는지 확인한 후 삭제합니다.
3. 새 활성화의 절대 종료 시각은 요청 시점부터 최대 1시간이며, 원본 Eligible 종료 시각을 넘지 않습니다. 해당 활성화를 허용하는 PIM 정책이 필요합니다. MFA·인증 컨텍스트·승인·정책을 우회하지 않습니다. 승인 대기/실패/불확정 요청에서는 삭제하지 않고 취소 또는 정리를 시도합니다.
4. 작업 성공·실패 시 이 실행이 만든 활성화만 `SelfDeactivate`로 해제하고 실제 삭제를 재조회합니다. Azure PIM은 활성화 후 5분 이내 해제를 허용하지 않으므로 정리에 최대 약 5분이 추가될 수 있습니다. 시작 전부터 활성화되어 있던 권한은 해제하지 않습니다.
5. 원본 Eligible 또는 그와 동일한 구독·실행자·역할을 삭제 대상으로 선택하면 해당 후보를 작업용 권한으로 사용할 수 없습니다. `--allow-self-removal`도 이 제한을 해제하지 않습니다. `--assume-no-pim`과 함께 사용할 수 없습니다.
6. PIM 활성화·취소·해제에도 API 호출 전 저널 intent를 동기 기록합니다. 정리 실패는 종료 코드 1과 `MANUAL PIM CLEANUP REQUIRED`로 알리며 요청 ID를 남깁니다. 프로세스 강제 종료 또는 저널 기록 실패 시에는 추가 미기록 변경을 시도하지 않으므로 PIM **My requests**에서 취소하거나 **My roles**에서 비활성화하고 확인해야 합니다. 새 요청에는 최대 1시간의 종료 시각이 설정됩니다.
7. 롤백은 임시 PIM 권한을 새로 만들거나 복원하지 않습니다. 미완료 정리 기록이 있으면 실제 상태를 읽어 남아 있는 권한/요청을 알리고, 수동 정리 후 재실행하면 해제를 확인합니다. 삭제 대상의 원래 권한 복원에 필요한 작업 권한은 별도로 활성화해야 할 수 있습니다.

이 옵션은 Azure의 마지막 관리자 보호나 권한 검사를 무시하는 강제 삭제 옵션이 아닙니다. 새 Eligible을 부여하거나 기존 Owner를 Eligible로 자동 변환하지 않습니다. 운영 환경에서는 격리된 테스트 구독에서 PIM 정책·전파·해제를 먼저 확인해야 합니다.

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

주요 검증은 범위 경계, 1,001건 페이지 조회, 조건 조합, MI 구분, PIM 기본 제외, Dry run의 쓰기 0건, 백업 실패/중단, 충돌, 만료 보존, PIM API 경로, 삭제 후 복원 및 재실행입니다. 구독 이름 OR/대소문자·RG 경계·MG 제외·이름 변경·역할 GUID 필터, PIM 임시 활성화/기존 활성화 재사용/최소 유지 시간/승인 취소/부분 프로비저닝/불확정 응답/실패 시 정리 및 수동 정리 후 확인도 모의 테스트로 검증합니다. 운영 적용 전에는 격리된 테스트 범위에서 PIM 하위 범위 조회의 완전성, 정책과 권한, Cloud Shell 저장소를 함께 확인해야 합니다.

2026-10-20 추가한 구독 이름 필터와 임시 PIM Owner 삭제 옵션은 모의 API로 검증했으며 실제 Azure 권한은 변경하지 않았습니다. 아래의 이전 실계정 검증 기록은 새 PIM 활성화/해제 기능의 실환경 검증 결과가 아닙니다.

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
- [구독 Display Name 조회](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/get?view=rest-resources-2022-12-01)
- [마지막 Owner 삭제 제한 및 PIM 사용 경로](https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting#symptom---cannot-delete-the-last-owner-role-assignment)
- [PIM 활성화·취소·5분 최소 유지](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-activate-your-roles)
- [대기 중인 PIM 요청 취소 API](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignment-schedule-requests/cancel?view=rest-authorization-2020-10-01)
- [PIM 인스턴스와 원본 할당 연결](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignment-schedule-instances/list-for-scope?view=rest-authorization-2020-10-01)
- [PIM 활성 할당 요청](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignment-schedule-requests/create?view=rest-authorization-2020-10-01)
- [PIM Eligible 할당 요청](https://learn.microsoft.com/en-us/rest/api/authorization/role-eligibility-schedule-requests/create?view=rest-authorization-2020-10-01)
- [PIM 라이선스 요건](https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals#privileged-identity-management)
- [Microsoft Graph 서비스 주체 유형](https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0)