# Hermes relay — схемы работы

Релей поверх `HermesDelegateV1` (EIP-7702 делегат, ERC-7821 batch executor). Пользователь **подписывает
намерение** (EIP-712), релей **платит газ** и **отправляет транзакцию**. Комиссия либо берётся в ERC-20
токене (`gasless`), либо спонсируется полностью (`battery`).

- Контракт: [contracts/v1/HermesDelegateV1.sol](../contracts/v1/HermesDelegateV1.sol)
- Nonce-менеджер: [contracts/v1/HermesV1.sol](../contracts/v1/HermesV1.sol)
- Сервер: [server/relay.ts](relay.ts), кодеки [server/hermes.ts](hermes.ts), API [server/openapi.yaml](openapi.yaml)

Обозначения в схемах: `--->` вызов/tx, меняющий состояние; `- - >` чтение (eth_call/эмуляция);
`===>` broadcast транзакции релеем; `[REQUIRED] / [OPTIONAL] / [BREAK_ON_FAIL]` — политика вызова.

---

## 0. Общая карта — что через что ходит

```
   +-----------+   /routes, /emulate, /send      +-----------+
   |  Кошелёк  | ------------------------------> |   Relay   |
   |   юзера   | <------------------------------ |  сервер   |
   +-----------+   uuid, sign(typedData), tx_hash+-----+-----+
        |  подпись EIP-712 (+ 7702-auth на 1й tx)      |
        |                                              | broadcast tx (релей платит газ)
        v                                              v
 ========================== on-chain (чейн) =========================

   battery / direct :  relay ===> userEOA.execute(...)
   delegate         :  relay ===> relayEOA.execute(...) ---> userEOA.execute(...)  (x2)

              userEOA.execute(...)
                    |
                    +--> HermesV1.useNonce()            (replay-защита, nonce)
                    +--> ERC-20.transfer(relay, amount) (fee, только gasless)
                    +--> Target.call(...)               (вызовы юзера)
```

Узлы: `userEOA` и (для delegate) `relayEOA` — обычные EOA с 7702-designator `0xef0100 ‖ HermesDelegateV1`,
то есть вызов такого EOA исполняет код делегата в его контексте (`address(this)` = сам EOA).

---

## 1. Базовые понятия

**EIP-7702 designator.** У EOA после делегации в коде лежит `0xef0100 ‖ <адрес делегата>` (23 байта).
Вызов такого EOA исполняет код `HermesDelegateV1` в контексте этого EOA (`address(this)` = сам EOA).

**ERC-7821 mode** (`bytes32`): `[0]` callType (`01` = batch), `[1]` execType (`00` atomic / `01` try),
`[6:10]` selector (`78210001` = signed opData / `00000000` = self-authorized), `[10:32]` payload.

**Два пути авторизации `execute(mode, executionData)`:**
- **no-opData** (`selector=00000000`): авторизация по `msg.sender` (сам EOA или EntryPoint). Payload —
  политики. Используется в proxy-self-call релея.
- **opData** (`selector=78210001`): `executionData = abi.encode(Call[], abi.encode(deadline, signature))`,
  подпись EOA над `Execute(bytes32 mode, Call[] calls, uint256 nonce, uint256 deadline)`. Replay-защита —
  nonce из `HermesV1`, срок — `deadline`.

**2-битные политики** (в try-режиме, `payload`, по 2 бита на вызов, вызов `i` в битах `[2i+1:2i]`):

| биты | политика | поведение при этом исходе вызова |
|------|----------|----------------------------------|
| `00` | OPTIONAL | падение логируется (`ERC7579TryExecuteFail`), батч продолжается |
| `01` | REQUIRED | падение ревертит весь батч |
| `10` | BREAK_ON_FAIL | падение логируется и завершает батч досрочно (tx успешна) |
| `11` | BREAK_ON_SUCCESS | успех завершает батч досрочно; падение логируется и продолжает |

Лимит try-батча — 88 вызовов (176 бит / 2). Реализация: `HermesDelegateV1._executeBatch`.

**Режимы, которые собирает сервер** ([hermes.ts](hermes.ts)):
```
OPDATA_ATOMIC_MODE  = 0x0100000000007821000100000000000000000000000000000000000000000000  // opData, atomic
PROXY_TRY_MODE      = 0x0101000000000000000000000000000000000000000000000000000000000001  // no-opData, try, [REQUIRED, OPTIONAL]
direct [REQ,BOF]    = 0x0101000000007821000100000000000000000000000000000000000000000009  // opData, try
direct [REQ,BOF,BOF]= 0x0101000000007821000100000000000000000000000000000000000000000029  // opData, try (payload 0x29)
```

---

## 2. Поток API

```
   Кошелёк                 Relay                  Chain / RPC
      |                      |                         |
      |   POST /routes       |                         |
      |--------------------->|   эмуляция газа (1x)     |
      |                      |- - - - - - - - - - - - >|
      |   fee по токенам     |                         |
      |<---------------------|                         |
      |                      |                         |
      |   POST /emulate      |                         |
      |--------------------->|   эмуляция (overrides)  |
      |                      |- - - - - - - - - - - - >|
      |   uuid + sign.{...}  |                         |
      |<---------------------|                         |
      |                      |                         |
      | sign typedData       |                         |
      | (eth_signTypedData)  |                         |
      |   POST /send         |                         |
      |--------------------->|   broadcast tx          |
      |                      |========================>|
      |   tx_hash            |                         |
      |<---------------------|                         |
```

- **`/routes`** — эмулирует один раз, возвращает примерный fee в каждом принимаемом токене. Без calldata.
- **`/emulate`** — точный токен → сервер подмешивает точный `transfer(relay, amount)`; возвращает готовый
  к подписи артефакт(ы) + `uuid`, привязанный к их EIP-712 digest.
- **`/send`** — эхо `uuid` + подписи; сервер сверяет, что присланный `typedData` пере-хешируется в quoted
  digest и несёт quoted mode, восстанавливает подпись в аккаунт, и отправляет.

---

## 3. Три пути доставки

`type` выбирает модель спонсорства; для `gasless` `path` выбирает механизм.

### 3.1 `type=battery` — полное спонсорство

Один атомарный батч юзера, релей вызывает аккаунт напрямую. Комиссия — виртуальная (off-chain).
Артефакт: `sign.user`. Ответ `mode=direct`. Релею делегат не нужен.

```
   relay ===(tx)===> userEOA.execute(OPDATA_ATOMIC, [userCalls], userSig)
                        |
                        +--> HermesV1.useNonce()            -> N
                        +--> Target.call(userCalls[*])
   (fee нет — виртуальная)
```

### 3.2 `type=gasless, path=direct` — один подписанный try-батч

Fee и вызовы юзера в **одном** батче: call 0 — `transfer(relay, amount)` (REQUIRED), остальные — вызовы
юзера (BREAK_ON_FAIL: если падают, батч завершается досрочно, но fee уже собран). Релей шлёт напрямую.
Артефакт: `sign.combined` (одна подпись). Ответ `mode=direct`. **Релею делегат НЕ нужен.** Самый дешёвый.

```
   relay ===(tx)===> userEOA.execute(TRY[REQ,BOF..], [fee, userCalls..], userSig)
                        |
                        +--> HermesV1.useNonce()               -> N
                        +--> call0  ERC-20.transfer(relay,amt)  [REQUIRED]
                        |          (упал -> revert всего батча)
                        +--> call1  Target.call(userCalls[0])   [BREAK_ON_FAIL]
                        +--> call2  Target.call(userCalls[1])   [BREAK_ON_FAIL]
                                   (упал -> log + стоп, tx OK, fee уже собран)
```

### 3.3 `type=gasless, path=delegate` — proxy через делегат релея

Fee и батч юзера — **две отдельные подписи**. Релей сам 7702-делегирован и делает self-call try-батч из
двух `execute` на аккаунте юзера: call 0 fee (REQUIRED), call 1 user (OPTIONAL — тихо глотается).
Артефакты: `sign.fee` (nonce N) + `sign.user` (nonce N+1). Ответ `mode=proxy`. Требует разовой
self-делегации релея (`ensureRelayDelegated`).

```
   relay ===(tx, self-call)===> relayEOA.execute(PROXY_TRY[REQ,OPT], [c0, c1])   // no-opData
                                   |
        c0 [REQUIRED] ------------>  userEOA.execute(OPDATA_ATOMIC, [fee], feeSig)
                                       +--> HermesV1.useNonce()            -> N
                                       +--> ERC-20.transfer(relay, amount)
                                   |
        c1 [OPTIONAL] ------------>  userEOA.execute(OPDATA_ATOMIC, userCalls, userSig)
                                       +--> HermesV1.useNonce()            -> N+1
                                       +--> Target.call(userCalls[*])
                                     (упал -> log + продолжить; fee из c0 уже собран)
```

### 3.4 `type=gasless, path=paymaster` — ERC-4337 (пока не реализовано)

Возвращает 400. Для сравнения: bundler шлёт `EntryPoint.handleOps([userOp])`, комиссия — `transferFrom`
в `postOp` токен-пеймастера. EntryPoint v0.8 `0x4337084D…108`, v0.9 `0x433709009B…009`.

```
   relay ===> EntryPoint.handleOps([userOp])
                 +--> userEOA.validateUserOp(...)         (проверка подписи)
                 +--> paymaster.validatePaymasterUserOp(...)
                 +--> userEOA.execute(no-opData, userCalls)
                 +--> paymaster.postOp(...) --> ERC-20.transferFrom(user, paymaster, cost)
```

---

## 4. Первая транзакция: EIP-7702 авторизация

Если EOA ещё не делегирован, `/emulate` возвращает `account.requiresAuthorization=true` и шаблон
`account.authorization`. Юзер подписывает 7702-tuple, `/send` шлёт **type-4** транзакцию с
`authorizationList=[auth]` — делегация и батч применяются атомарно.

```
   relay ===(type-4 tx, authorizationList=[userAuth])===> userEOA
             |
             +-- сначала применяется 7702-designator (userEOA -> HermesDelegateV1)
             +-- затем исполняется execute(...) как обычно
```

Надбавка в квоте: `gas.authorizationGas` = 12500 (существующий аккаунт) / 25000 (пустой). Для `delegate`
дополнительно нужен разово делегированный `relayEOA` (`ensureRelayDelegated`, отдельная type-4 tx).

---

## 5. Эмуляция газа без ключа юзера

На `/emulate`/`/routes` подписи юзера ещё нет. Через `eth_call`/`eth_estimateGas` **state overrides**
подставляется код на три адреса:

```
   userEOA  ->  HermesDelegateEmulatorV1   (тот же execute, но _validateSignature принимает
                                            любую валидную ECDSA-подпись; сервер подписывает
                                            одноразовым ключом -> ecrecover входит в оценку)
   0x..7702 ->  HermesNonceEmulatorV1       (газ-двойник HermesV1; текущий nonce юзера зеркалится
                                            в слот -> SSTORE useNonce() стоит как в реале)
   0x..7703 ->  HermesGasMeterV1            (оборачивает вызов в gasleft() и возвращает газ как
                                            return data -> для нод, где eth_estimateGas не берёт
                                            overrides, напр. hardhat)
```

**Три тира** (`gas.source`): `estimateGas` (нода считает всю tx) → `gasMeter` (через `eth_call` +
газометр, `+ intrinsic 21k + calldata`) → `heuristic` (нода без overrides). Итог × буфер 1.2 =
`gas.charged`, из него считается `amount`.

---

## 6. UUID-биндинг квоты

`/emulate` генерит `uuid` → хранит `{digest, mode}` каждого подписываемого батча. `/send` требует `uuid`,
пере-хеширует присланный `typedData`, сверяет с сохранённым digest и mode, проверяет recover подписи в
аккаунт. Любая правка (суммы, вызовы, nonce, deadline, mode) ломает digest → 400. `uuid` одноразовый —
удаляется после успешного бродкаста (реплей → 400).

```
   /emulate:  uuid -> { role: {digest, mode} }      (direct: {combined}; delegate: {fee,user}; battery: {user})
   /send:     hash(присланный typedData) == quote.digest  ?
              recover(digest, signature) == account      ?  -> broadcast : 400
```

---

## 7. Сравнение по газу

Steady-state (прогретые слоты nonce/counter/баланс релея), on-chain `gasUsed`, N — число вызовов юзера.
Все три — комиссия в ERC-20 токене, одна ETH-транзакция. Замерено на локальной ноде (hardhat), тир
`gasMeter`; direct-батч использует политики `[REQ, BOF×N]`.

```
   N=1 |###############################                       |  direct     72 776
       |########################################              |  delegate   95 317
       |#############################################         |  paymaster 108 358
       |####################                                  |  battery   ~53 072  (без fee)
```

| N | direct-batch `[REQ, BOF×N]` · single-delegate · 1 tx | proxy · double-delegate · 2 батча | 4337 + ERC-20 paymaster |
|---|---|---|---|
| 1 | 72 776 | 95 317 | 108 358 |
| 2 | 78 618 | 101 102 | 113 342 |
| 3 | 84 496 | 106 922 | 118 387 |

- `delegate` дороже `direct` на ~22.5k (фикс.): вторая подпись (ecrecover + хеш), второй `useNonce`,
  внешний execute + второй inner-call, лишняя calldata. Взамен — раздельные политики fee/user.
- `paymaster` дороже `delegate` на ~12–14%: синглтон-EntryPoint (оркестрация, 2D-nonce, deposit/refund) +
  отдельный `postOp` с `transferFrom`. `direct`/`delegate` берут fee inline.
- `battery` (прямой вызов, без fee) ≈ 53k.

Разово (амортизируется): self-делегация релея для `delegate` (~12.5k, EIP-7702) и 7702-авторизация юзера
на первой tx (12.5k/25k).

---

## 8. Политика релея по флагам

- Fee всегда **REQUIRED** (`direct`: call 0; `delegate`: call 0 внешнего try-батча) → fee не пропускается.
- Вызовы юзера никогда не REQUIRED в контексте, где их падение могло бы откатить уже собранный fee:
  `direct` → **BREAK_ON_FAIL**, `delegate` → **OPTIONAL**. В обоих случаях упавший батч юзера не теряет fee
  и не ревертит транзакцию.

