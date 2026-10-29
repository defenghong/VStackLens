"""Read-only adapters for desktop presentation; no rule or persistence changes."""
import json,sqlite3
from pathlib import Path
from vstacklens.desktop.presentation import ui_text,power_state

def display(value,unit=""):
    if value is None or value=="":return "—"
    if isinstance(value,bool):return "已启用" if value else "未启用"
    if isinstance(value,(dict,list)):return ui_text(json.dumps(value,ensure_ascii=False))
    return ui_text(str(value))+unit

def inventory(db,run_id):
    path=Path(db)
    if not path.is_file() or not run_id:return []
    with sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT object_type,object_name,object_key,path,properties_json FROM inventory_objects WHERE run_id=? ORDER BY object_type,object_name",(run_id,)).fetchall()
    result=[]
    for row in rows:
        payload=json.loads(row["properties_json"] or "{}");props=payload.get("properties",payload)
        result.append({**dict(row),"properties":props if isinstance(props,dict) else {}})
    return normalize_inventory(result)

def normalize_inventory(records):
    """Resolve only explicitly recorded inventory paths and named host relations."""
    clusters={r["path"]:r["object_name"] for r in records if r["object_type"]=="ClusterComputeResource"}
    hosts={r["object_name"]:r for r in records if r["object_type"]=="HostSystem"}
    for record in records:
        p=record["properties"];location=p.get("asset_location","")
        if record["object_type"]=="HostSystem" and not p.get("cluster_name") and location in clusters:p["cluster_name"]=clusters[location]
        if record["object_type"]=="Datastore" and not p.get("cluster_name"):
            names=p.get("datastore_cluster_names",[])
            if len(names)==1:p["cluster_name"]=names[0]
        if record["object_type"]=="VirtualMachine" and not p.get("host_name"):
            names=[part[3:] for part in location.split(" / ") if part.startswith("主机 ")]
            if len(names)==1 and names[0] in hosts:p["host_name"]=names[0]
    for record in records:
        p=record["properties"]
        if record["object_type"]=="VirtualMachine" and not p.get("cluster_name"):
            host=hosts.get(p.get("host_name"))
            if host and host["properties"].get("cluster_name"):p["cluster_name"]=host["properties"]["cluster_name"]
    mapped = [r for r in records if r["object_type"]=="VirtualMachine" and r["properties"].get("host_name") in hosts]
    for name,host in hosts.items():
        if mapped:host["properties"]["vm_count"] = sum(r["properties"].get("host_name")==name for r in mapped)
    return records

def asset_fields(item,props):
    common=[("对象名称",item.object_name),("对象类型",ui_text(item.object_type)),("完整位置",item.location or "—"),("已有属性摘要",ui_text(item.detail))]
    layouts={
        "HostSystem":[("所属集群",("cluster_name",),""),("ESXi 版本",("host_version","version","esxi_version"),""),("CPU",("cpu_core_count","host_pcpu_count","host_cpu_capacity_mhz"),""),("内存",("host_memory_capacity_mb","memory_mb")," MB")],
        "VirtualMachine":[("所属主机",("host_name",),""),("所属集群",("cluster_name",),""),("CPU",("vcpu_count",)," 核"),("内存",("memory_mb","vm_memory_configured_mb")," MB"),("电源状态",("power_state",),"")],
        "Datastore":[("归属集群",("cluster_name",),""),("存储类型",("datastore_filesystem_type",),""),("容量使用率",("used_percent","datastore_usage_percent"),"%"),("可访问",("accessible",),"")],
        "ClusterComputeResource":[("主机数",("host_count",)," 台"),("HA",("ha_enabled",),""),("DRS",("drs_enabled",),""),("CPU 使用率",("cluster_cpu_usage_avg",),"%")],
    }
    fields=[]
    for label,keys,unit in layouts.get(item.object_type,[]):
        key=next((k for k in keys if props.get(k) is not None),keys[0]);value=props.get(key)
        if label=="CPU" and key=="host_cpu_capacity_mhz":unit=" MHz"
        elif label=="CPU" and key=="cpu_core_count":unit=" 核"
        elif label=="CPU" and key=="host_pcpu_count":unit=" 个逻辑处理器"
        fields.append((label,power_state(value) if label=="电源状态" else display(value,unit)))
    return fields+common

def related_assets(record,records):
    """Use explicit recorded relationships only; never guess from an absent field."""
    kind,name=record["object_type"],record["object_name"]
    if kind=="HostSystem":return [r for r in records if r["object_type"]=="VirtualMachine" and r["properties"].get("host_name")==name]
    if kind=="ClusterComputeResource":return [r for r in records if r["properties"].get("cluster_name")==name]
    if kind=="Datastore":return [r for r in records if r["object_type"]=="VirtualMachine" and name in r["properties"].get("datastore_names",[])]
    return []

def run_target(db,run_id):
    path=Path(db)
    if not path.is_file() or not run_id:return "—"
    with sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True) as conn:
        row=conn.execute("SELECT v.host FROM inspection_runs r JOIN vcenters v ON v.vcenter_id=r.vcenter_id WHERE r.run_id=?",(run_id,)).fetchone()
    return row[0] if row and row[0] else "—"

def nic_link_state(nic):
    state = nic.get("link_state")
    if state in {"up","down"}:return "链路正常" if state=="up" else "链路断开"
    if isinstance(nic.get("link_up"),bool):return "链路正常" if nic["link_up"] else "链路断开"
    return display(nic.get("connection_state"))
