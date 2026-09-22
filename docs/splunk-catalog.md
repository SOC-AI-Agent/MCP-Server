# Export Splunk catalog — เตรียมข้อมูลก่อนใช้ production

agent ค้น Splunk ด้วย **ชื่อ field** ถ้าเดาผิดมันจะรายงานว่า "ไม่พบอะไร" อย่างมั่นใจ
ทั้งที่ข้อมูลมีอยู่ — อันตรายกว่า error เพราะไม่มีอะไรฟ้อง

เอกสารนี้คือวิธีดึงรายการ index / sourcetype / field ออกมาจาก Splunk จริง
เพื่อเอาไปเติมให้ agent รู้

---

## ทางที่แนะนำ — เรียกผ่าน `/catalog` ของ connector

`soc-mcp-splunk` มี endpoint ให้ดึง catalog ได้เลย ใช้ token ที่ตั้งไว้แล้วใน `.env`
ไม่ต้องเอา credential ของ Splunk ออกมาที่เครื่องใคร

```bash
docker compose exec soc-mcp-splunk python -c "
import urllib.request, os, json
req = urllib.request.Request('http://localhost:8200/catalog',
    headers={'Authorization': 'Bearer ' + os.environ['MCP_AUTH_TOKEN']})
print(urllib.request.urlopen(req).read().decode())" | python3 -m json.tool
```

หรือจากเครื่องอื่นใน network เดียวกัน:

```bash
curl -s "http://soc-mcp-splunk:8200/catalog" -H "Authorization: Bearer $MCP_AUTH_TOKEN"
```

| พารามิเตอร์ | default | |
| --- | --- | --- |
| `values` | `false` | `true` = คืนค่าตัวอย่างจริงด้วย |
| `sample` | `200` | สุ่มกี่ event ต่อ sourcetype (สูงสุด 5000) |
| `max_sourcetypes` | `50` | จำกัด fan-out (สูงสุด 200) |
| `index` | ทั้ง allowlist | เจาะ index เดียว |

### ทำไมถึงปลอดภัยกว่าสคริปต์

| | สคริปต์ | `/catalog` |
| --- | --- | --- |
| TLS | `curl -sk` ไม่ตรวจ cert | ใช้ `SPLUNK_VERIFY_SSL` ร่วมกับทั้งระบบ |
| credential | โผล่ใน `ps` ถ้าใช้ `user:password` | อยู่ใน container ไม่ออกมา |
| ค่าตัวอย่าง | ได้เสมอ | **ไม่ได้เป็น default** ต้อง `?values=true` |
| ขอบเขต | `index=*` ดิบ | เคารพ `SPLUNK_ALLOWED_INDEXES` |
| audit | ไม่มี | log ทุกครั้งว่าใครเรียก ขอ values ไหม |
| ตรงกับที่ agent เห็น | ขึ้นกับ credential ที่ใช้รัน | ใช้ token เดียวกับ agent เป๊ะ |

### ⚠️ Agent เข้าถึงไม่ได้ — โดยตั้งใจ

`/catalog` เป็น **custom route ไม่ใช่ MCP tool** จึงไม่โผล่ใน `tools/list` model
มองไม่เห็นและเรียกไม่ได้

ยืนยันได้:

```bash
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | sed -n 's/^data: //p' \
  | python3 -c "import json,sys; print([t['name'] for t in json.load(sys.stdin)['result']['tools']])"
```
```
['list_indexes', 'search_events', 'alert_frequency', 'related_events']
```

**เหตุผล:** tool ที่ "สำรวจทุก index ทุก field พร้อมค่าตัวอย่าง" อยู่ในมือ model
ที่อ่าน alert ซึ่งผู้โจมตีแต่งได้ = prompt injection ครั้งเดียวก็พาข้อมูลจริง
เข้า context แล้วออกไปอยู่ในสรุปที่ Tier 1 อ่าน และถูกเก็บลง `ai_jobs`

ขั้นตอนที่ตั้งใจให้เป็นคือ: **คนดึง catalog ครั้งเดียว → คนคัดว่าอะไรควรให้ model รู้
→ เขียนลง data guide** model เห็นเฉพาะสิ่งที่คนเลือกใส่ ไม่ใช่ทั้ง estate

ไม่มี token ก็เรียกไม่ได้ (`/health` เป็น path เดียวที่ไม่ต้อง auth):
```bash
curl -s -o /dev/null -w '%{http_code}\n' http://soc-mcp-splunk:8200/catalog
# 401
```

---

## ทางเลือก — สคริปต์ สำหรับคนที่ไม่มีสิทธิ์เข้า container

> ⚠️ สคริปต์นี้เขียนไว้ตอนยังไม่มี `/catalog` ใช้ได้ แต่มี 3 จุดที่ `/catalog` ไม่มี:
> ใช้ `curl -sk` (**ไม่ตรวจ cert**), รหัสโผล่ใน `ps` ถ้าใช้ `user:password`,
> และ**คืนค่าตัวอย่างจริงเสมอ** ไฟล์ที่ได้จึงเป็นข้อมูล production —
> ห้าม commit ห้ามแปะใน ticket

## ใช้

```bash
export SPLUNK_URL='https://splunk.example.com:8089'   # management port ไม่ใช่ web 8000
export SPLUNK_AUTH='Bearer eyJ…'                      # หรือ 'user:password'

./scripts/export_splunk_catalog.sh
```

ปรับได้:

| ตัวแปร | default | ความหมาย |
| --- | --- | --- |
| `WINDOW` | `-30d` | ช่วงเวลาที่สำรวจ |
| `SAMPLE` | `200` | สุ่มกี่ event ต่อ sourcetype เพื่อดู field |
| `OUT` | `splunk-catalog` | โฟลเดอร์ผลลัพธ์ |
| `SPLUNK_INSECURE` | `1` | `1` ข้าม TLS verify (lab cert self-signed), `0` ตรวจจริง |

ถ้าเรียกไม่สำเร็จ script จะหยุดและบอกสาเหตุ — token หมดอายุ (exit 22),
cert ตรวจไม่ผ่าน (60), ต่อไม่ติด (7), timeout (28) เดิม 401 กลับมาเป็น body
ว่าง แล้ว export จบสวยๆ พร้อม catalog ที่บอกว่า estate นี้ไม่มี index เลย

---

## รันอัตโนมัติด้วย GitHub Actions

[`.github/workflows/splunk-catalog.yml`](../.github/workflows/splunk-catalog.yml)
ดึง export มาเก็บที่ `mcp-server/Splunk/table/` **เฉพาะตอนที่ยังไม่มี**
ถ้ามีครบแล้วจะข้าม ใช้เวลาไม่กี่วินาที

### "มีแล้ว" แปลว่าอะไร

ไม่ใช่แค่ folder มีอยู่ export ที่ตายกลางคันก็ทิ้ง folder ไว้เหมือนกัน
[`verify_catalog_export.py`](../scripts/verify_catalog_export.py) เช็กว่า
sourcetype ทุกตัวที่ enumerate เจอมีไฟล์ field ครบ และทุกไฟล์ parse ได้

workflow เรียกตัวเดียวกันนี้สองครั้ง — ก่อน export เพื่อตัดสินว่าต้องดึงไหม
และหลัง export เพื่อตัดสินว่าจะ commit ไหม นิยามเดียวกัน จะได้ไม่มีวันที่
สองอันตอบไม่ตรงกัน แล้ว catalog ครึ่งใบถูก commit เพราะเช็กตอนแรกหลวมกว่า

export ลง staging dir เสมอ ไม่ลงตรง repo ถ้าตายกลางทาง catalog เดิมไม่ถูกแตะ

### ต้องตั้งอะไร

| ประเภท | ชื่อ | ใช้ทำอะไร |
| --- | --- | --- |
| secret | `SPLUNK_URL` | management port เช่น `https://splunk.internal:8089` |
| secret | `SPLUNK_TOKEN` | Splunk auth token หรือ `user:password` |
| variable | `CATALOG_RUNNER` | label ของ runner — default `ubuntu-latest` |
| variable | `SPLUNK_INSECURE` | `1` ถ้า cert self-signed — default `0` |
| variable | `CATALOG_WINDOW` | default `-30d` |
| variable | `CATALOG_SAMPLE` | default `200` |

> **runner ต้องมองเห็น Splunk** GitHub-hosted runner อยู่บน internet
> เข้า Splunk ใน network ภายในไม่ได้ ต้องใช้ self-hosted runner ข้างในแล้วชี้
> `CATALOG_RUNNER` มาที่มัน

### เมื่อไหร่มันรัน

`push` เข้า main และกดเองจากหน้า Actions ตอนกดเองมี checkbox `force`
สำหรับ export ทับของเดิม — กฎ "มีแล้วไม่ดึง" เป็น default แต่ไม่ได้แปลว่า
ห้าม refresh ตลอดชีพ estate เปลี่ยนได้

ถ้า secret ยังไม่ได้ตั้ง: กดเอง = fail ชัดๆ, push = เตือนแต่ไม่ fail
เพราะ job ที่ต้องสำเร็จครั้งเดียวไม่ควรทำให้ทุก commit ขึ้นกากบาทแดง
คนจะเลิกสนใจ แล้วก็จะเลิกสนใจอันที่สำคัญด้วย

### ไม่ต้อง commit `table/` เองล่วงหน้า

commit ไฟล์เปล่าหรือ export จาก lab ลงไปจะทำให้ CI ข้ามตลอดไป
แล้ว production จะไม่เคยได้ catalog จริง ปล่อยว่างไว้ให้ workflow สร้าง

---

## ได้ไฟล์อะไรออกมา

| ไฟล์ | รูปแบบ | เอาไปทำอะไร |
| --- | --- | --- |
| `catalog.md` | Markdown | **วางลง data guide / system prompt ของ agent ได้เลย** |
| `field-map.json` | JSON | ตั้งต้นสำหรับ `SPLUNK_FIELD_MAP` |
| `indexes.json` | JSON | index → sourcetype + จำนวน event |
| `fields__<index>__<sourcetype>.json` | JSON | field ทั้งหมดของ sourcetype นั้น พร้อมตัวอย่างค่า |
| `datamodels.json` | JSON | data model ที่ติดตั้ง — บอกว่า estate นี้ normalize เป็น CIM แล้วหรือยัง |

### `catalog.md` — สำหรับคนกับ model อ่าน

```markdown
CIM data models: **none** — fields are not normalised

### index `main` · sourcetype `fortigate`

| field | distinct | examples |
| --- | --- | --- |
| `action` | 3 | blocked, accept, close |
| `srcip` | 4 | 10.1.100.11, 10.1.100.44 |
| `dstip` | 4 | 45.83.122.9, 185.220.101.7 |
| `host` | 1 | 192.168.65.1 |
```

ตัวอย่างค่าคือจุดสำคัญ — เห็นทันทีว่า `host` คือ **forwarder** (`192.168.65.1`)
ไม่ใช่เครื่องต้นทาง ส่วน IP จริงอยู่ที่ `srcip`

### `field-map.json` — ตั้งต้น ไม่ใช่ของสำเร็จ

สคริปต์เดาจากชื่อ field ให้:

```json
{
  "ip":     ["dstip", "srcip"],
  "user":   ["user"],
  "host":   ["devname", "host"],
  "hash":   [],
  "domain": []
}
```

> ⚠️ **ต้องมีคนตรวจก่อนใช้** — สคริปต์เดาจากชื่อ ไม่รู้ความหมาย
> ตัวอย่างข้างบนใส่ `host` ไว้ในกลุ่ม host ทั้งที่จริงมันคือ forwarder ควรเอาออก
> และ `devname` คือชื่ออุปกรณ์ firewall ไม่ใช่เครื่องปลายทาง

---

## 4 ขั้นที่สคริปต์ทำ

### 1. เช็กว่า estate นี้เป็น CIM หรือยัง

```
| rest /services/data/models | table title
```

**ถ้ามี data model นอกเหนือจาก `internal_*`** แปลว่า normalize แล้ว — `src`, `dest`,
`user` มีความหมายมาตรฐาน field map ที่ hardcode ไว้ใน
[`mcp-server/Splunk/server.py`](../mcp-server/Splunk/server.py) ก็จะถูกต้องอยู่แล้ว
งานที่เหลือน้อยลงมาก

**ถ้าไม่มี** ต้องแมปเองทุก sourcetype

### 2. index + sourcetype

```
| tstats count where index=* by index, sourcetype
```

`tstats` อ่านจาก tsidx ไม่สแกน event — เร็วแม้ estate ใหญ่

ทางเลือกที่เร็วกว่าอีก ถ้าต้องการแค่ sourcetype:
```
| metadata type=sourcetypes index=*
```
อ่าน metadata ล้วน ได้ `firstTime`/`lastTime` มาด้วย — ใช้ดูว่า sourcetype ไหนตายแล้ว

### 3. field ของแต่ละ sourcetype

```
search index="X" sourcetype="Y" | head 200 | fieldsummary maxvals=3
```

> **`| walklex` ใช้ไม่ได้กับกรณีทั่วไป** ถึงมันจะดึงชื่อ field ได้โดยไม่สแกน event
> แต่มันอ่านจาก **lexicon** ซึ่งมีแต่ *indexed field* ส่วน log แบบ `key=value`
> (FortiGate, syslog ส่วนใหญ่) เป็น **search-time extraction** ไม่อยู่ใน lexicon
> ทดสอบแล้วได้ 0 แถว — ต้องใช้ `fieldsummary` เท่านั้น

### 4. สรุปเป็น `catalog.md` + `field-map.json`

---

## ข้อควรระวัง

**sampling ไม่เห็นทุก field** — `| head 200` เห็นเฉพาะ field ที่ปรากฏใน 200 event แรก
FortiGate `type=utm` (virus, IPS) มี field ที่ `type=traffic` ไม่มี ถ้าสัดส่วนน้อยอาจหลุด

แก้: เพิ่ม `SAMPLE` หรือสุ่มให้กระจาย
```bash
SAMPLE=2000 ./scripts/export_splunk_catalog.sh
```

**ช่วงเวลามีผล** — `WINDOW=-30d` ไม่เห็น sourcetype ที่หยุดส่งไปแล้ว หรือที่เพิ่งเริ่ม
ตรวจจาก `firstTime`/`lastTime` ของ `| metadata`

**สิทธิ์จำกัดผลลัพธ์** — ได้เฉพาะ index ที่ token เห็น ซึ่ง**เป็นเรื่องดี**: มันบอก
ตรงๆ ว่า agent จะเห็นอะไรได้บ้างจริงๆ รันด้วย token ตัวเดียวกับที่ agent จะใช้
จะได้ catalog ที่ตรงกับความจริง

**ต้นทุนบน estate ใหญ่** — ข้อ 3 ยิง search หนึ่งครั้งต่อ sourcetype ถ้ามี 200
sourcetype ก็ 200 search คุยกับ Splunk admin ก่อน หรือจำกัดด้วยการแก้ `_pairs.txt`
ให้เหลือเฉพาะที่สนใจ

---

## แบ่ง query agent อัตโนมัติ

production มี sourcetype เป็นร้อย ใส่ prompt เดียวไม่ได้ — agent หนึ่งตัวที่ต้องรู้
ทั้ง firewall, EDR, AD และ email จะยาวเกินและเลือกผิดบ่อย

`plan_query_agents.py` จัดกลุ่มให้ตาม**คำถามที่ Tier 1 ถาม** ไม่ใช่ตาม vendor:

```bash
curl -s "$MCP/catalog" -H "Authorization: Bearer $MCP_AUTH_TOKEN" \
  | python3 scripts/plan_query_agents.py -o build/
```

ยังไม่มี export จริงก็ลองได้เลย — มีตัวอย่างรูปแบบ production ให้:

```bash
python3 scripts/plan_query_agents.py mcp-server/Splunk/catalog/catalog-export.example.json -o build/
```

```
27 sourcetypes -> 5 query agents   (budget 2730 tokens each, 33% of 8192)

  network     11 sourcetypes  ~  585 tokens
  endpoint     5 sourcetypes  ~  457 tokens
  identity     5 sourcetypes  ~  456 tokens
  email        2 sourcetypes  ~  382 tokens
  alert        2 sourcetypes  ~  375 tokens
```

### ได้ไฟล์อะไร

```
build/
  catalog/<domain>.json          catalog เฉพาะโดเมน -> SPLUNK_CATALOG_FILE
  agents/<domain>-query.json     POST ไป LLM server ได้เลย
  agents/_analyst-delegates.json PATCH ใส่ agent วิเคราะห์
```

```bash
for f in build/agents/*-query.json; do
  curl -s -X POST localhost:8400/agents -H 'Content-Type: application/json' -d @"$f"
done
curl -s -X PATCH localhost:8400/agents/soc-analyst \
  -H 'Content-Type: application/json' -d @build/agents/_analyst-delegates.json
```

### โดเมนมาจากไหน — อ่านก่อนใช้

**5 โดเมนนั้นเขียนไว้ในโค้ด ไม่ได้เรียนรู้จากข้อมูล** — network, endpoint,
identity, email, alert เป็นการแบ่งที่ SOC ใช้กันอยู่แล้ว และการ fix ไว้ทำให้
**อธิบายได้** ว่าทำไม sourcetype หนึ่งไปอยู่กลุ่มนั้น ซึ่ง embedding บอกไม่ได้

แต่มันก็คือการเดา estate ของคุณ ถ้ามี OT/ICS, cloud audit หรือ database log
5 โดเมนนี้ครอบไม่ถึง มีสองทางออก:

**1. เขียนตารางของตัวเอง — `--domains`**

```bash
python3 scripts/plan_query_agents.py export.json --domains my-domains.json -o build/
```

```json
{
  "perimeter": {
    "asks": "traffic crossing the boundary",
    "roles": {"src_ip": 3, "dest_ip": 3},
    "fields": {"srcip": 3, "dstip": 3, "c_ip": 3, "cs_host": 3},
    "name": {"fortigate|pan|proxy|bluecoat|zscaler": 4}
  }
}
```

ตัวเลขคือน้ำหนัก — สัญญาณที่บอกได้แน่นอนให้สูง (`parent_process` = 4),
สัญญาณที่โผล่ทุกที่ให้ต่ำ (`user` = 2)

**2. ให้มันหากลุ่มเอง — `--discover`**

ไม่ใช้ตารางเลย จัดกลุ่มจาก **field ที่ใช้ร่วมกัน** (Jaccard) แล้วค่อยเสนอชื่อ
กลุ่มไหนไม่ตรงกับตารางจะได้ชื่อ `unnamed-N` ซึ่งเป็นคำตอบที่ซื่อสัตย์สำหรับ
ข้อมูลที่ตารางไม่ได้เขียนเผื่อไว้

```bash
python3 scripts/plan_query_agents.py export.json --discover --similarity 0.15 -o build/
```

### ⚠️ `--discover` ทำงานได้ดีเท่าที่ estate มีคำศัพท์ร่วมกัน

ทดสอบกับ sample แล้วได้แบบนี้:

| similarity | ผล |
| --- | --- |
| 0.25 | **18 กลุ่ม** — แตกเกินไป |
| 0.15 | 8 กลุ่ม — พอใช้ |
| 0.10 | 8 กลุ่ม network รวมกันได้ดี |
| 0.05 | **รวม identity เข้า endpoint** — หลอมเกินไป |

และไม่ว่าค่าไหน **Bluecoat แยกเดี่ยวเสมอ** เพราะมันใช้ `c_ip`, `cs_host`,
`cs_uri_stem` ซึ่งไม่มีตัวอักษรร่วมกับ `src_ip` หรือ `clientip` ของเจ้าอื่นเลย

ทั้งสามชื่อแปลว่า "source IP" เหมือนกัน แต่ clustering จากชื่อ field มองไม่เห็น

**นี่คือเหตุผลที่ตารางโดเมนมีอยู่** — มันคือที่เก็บความรู้ว่า `c_ip` กับ `clientip`
กับ `src_ip` หมายถึงสิ่งเดียวกัน ซึ่งเป็นข้อเท็จจริงที่ต้องมีคนบอก

ยิ่ง estate ไม่ได้ normalize เป็น CIM `--discover` ยิ่งแตก — ซึ่งก็คือ
estate เดียวกับที่ต้องการ catalog มากที่สุด

### วิธีใช้ให้คุ้มที่สุด

**รันทั้งสองแบบแล้วเทียบ**

- ตรงกัน → มั่นใจได้
- `--discover` แยกสิ่งที่ตารางรวม → ตารางกำลังรวมของที่ field ไม่เหมือนกันจริง
  อาจถูก (ต่าง vendor ความหมายเดียวกัน) หรือผิด (รวมมั่ว) — ต้องดู
- `--discover` รวมสิ่งที่ตารางแยก → อาจมีโดเมนที่ตารางยังไม่มีชื่อเรียก

### มันตัดสินจากอะไร

ให้คะแนนจาก **ชื่อ field**, **role** (ถ้ามี) และ **ชื่อ sourcetype** — น้ำหนักต่างกัน
ตามว่าสัญญาณนั้นบอกอะไรได้จริง `parent_process` แทบเป็นหลักฐานว่าเป็น endpoint
ส่วน `user` โผล่เกือบทุกที่จึงแทบไม่มีน้ำหนัก

**sourcetype หนึ่งเข้าได้หลายโดเมน** — VPN มีทั้ง `user` และ `src_ip` ก็อยู่ทั้ง
identity และ network การบังคับให้เลือกข้างจะทำให้คำถามที่มันตอบได้ดีที่สุดหายไป

### สิ่งที่มันบอกและคุณต้องตัดสินเอง

| รายงาน | หมายถึง |
| --- | --- |
| `OVER BUDGET` | โดเมนนั้นใหญ่เกิน prompt เดียว ต้องซอยต่อ |
| `matched no domain` | `ops`, `compliance`, `backup` — มักไม่ควรอยู่ในมือ agent วิเคราะห์เลย |
| `need review` | คะแนนไม่ชัด หรือเข้าหลายโดเมน |

เกณฑ์งบคือ **1/3 ของ `num_ctx`** — ที่เหลือต้องพอให้ alert, tool schema และผลลัพธ์
ที่วนกลับมาหลายรอบ

### ยังต้องกรอกเอง

prompt ที่ได้เต็มไปด้วย `TODO` — `purpose` กับ `roles` เป็นส่วนที่ export บอกไม่ได้
ต้องคนเขียน เหมือนกับที่ `make_catalog_template.py` ทำ

ปล่อย `TODO` ไว้ agent จะยังเลือก index ได้ แต่จะเดาชื่อ field ผิด ซึ่งคือปัญหา
ที่เอกสารนี้มีไว้แก้ตั้งแต่ต้น

> **เริ่มจาก agent เดียวก่อน** ใส่เฉพาะ sourcetype ที่ alert จาก SOAR แตะจริง
> ส่วนใหญ่ 10-20 ตัว ไม่ใช่ 200 แล้วค่อยแบ่งเมื่อวัดแล้วว่าเกินงบ
> — catalog ควรมีเท่าที่ agent ใช้ ไม่ใช่เท่าที่ Splunk มี

---

## เอาผลไปใช้ต่อ

**1. ใส่ `catalog.md` ลง data guide ของ agent**

ตัดเฉพาะ sourcetype ที่เกี่ยวข้อง อย่าใส่ทั้งหมด — `num_ctx` มีจำกัด และ field
ที่ไม่เกี่ยวคือ token ที่ขโมยมาจากการ reasoning

เขียนความหมายกำกับด้วย เพราะ export บอกแค่ชื่อ:
```
index fortigate (sourcetype fortigate_traffic)
  srcip   = source IP        ใช้ตัวนี้ ไม่ใช่ host
  dstip   = destination IP
  host    = forwarder ที่ส่ง log เข้ามา ไม่ใช่เครื่องต้นทาง
  devname = ชื่ออุปกรณ์ firewall
```

**2. ตรวจ `field-map.json` แล้วใส่เป็น `SPLUNK_FIELD_MAP`**

ตัวนี้ `related_events` ใช้ ซึ่ง model แก้ไม่ได้ — ต้องถูกตั้งแต่ config

**3. ตั้ง `SPLUNK_ALLOWED_INDEXES` จาก `indexes.json`**

หรือตั้ง `*` แล้วให้ role ของ token เป็นตัวคุมขอบเขต — ดู [TOKENS.md](tokens.md)

---

## ตรวจว่าใช้ได้จริง

หลังตั้งค่าเสร็จ ยิง tool ตรงๆ ด้วย field ที่เพิ่งแมป ([TESTING.md](testing.md) ชั้น 2):

```bash
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
       "name":"search_events",
       "arguments":{"index":"fortigate","filters":{"srcip":"10.1.100.11"},"max_count":3}}}'
```

ได้ข้อมูลกลับมา = แมปถูก ได้ `count: 0` ทั้งที่รู้ว่ามีข้อมูล = ยังผิด
