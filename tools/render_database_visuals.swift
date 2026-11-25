import Foundation
import CoreGraphics
import CoreText
import ImageIO

// Render shareable figures from the same sanitized snapshot used by the explorer.
let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let data = try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("snapshot.json"))) as! [String: Any]
let counts = data["counts"] as! [String: Int]
let stats = data["stats"] as! [String: Any]
let samples = data["samples"] as? [[String: Any]] ?? []
let tables = data["tables"] as! [[String: Any]]
let status = data["status"] as? [String: Any]
let width: CGFloat = 1600, height: CGFloat = 1040
let scale: CGFloat = 2
let bg = "#0b101b", panel = "#111a29", lineColor = "#2b3b52"
let fg = "#e5ecf6", muted = "#a2b2c9", cyan = "#69dfdb", purple = "#b9a1ff"
let green = "#7cdbac"
var context: CGContext!
func color(_ hex: String) -> CGColor {
    let v = UInt32(hex.dropFirst(), radix: 16)!
    return CGColor(red: CGFloat((v >> 16) & 255) / 255, green: CGFloat((v >> 8) & 255) / 255, blue: CGFloat(v & 255) / 255, alpha: 1)
}
func rect(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, _ fill: String, _ radius: CGFloat = 0, _ stroke: String? = nil) {
    let p = CGPath(roundedRect: CGRect(x: x, y: height-y-h, width: w, height: h), cornerWidth: radius, cornerHeight: radius, transform: nil)
    context.addPath(p)
    context.setFillColor(color(fill))
    if let s = stroke {
        context.setStrokeColor(color(s)); context.setLineWidth(1)
        context.drawPath(using: .fillStroke)
    } else { context.fillPath() }
}
func text(_ s: String, _ x: CGFloat, _ y: CGFloat, _ size: CGFloat = 14, _ ink: String = fg, _ font: String = "HelveticaNeue") {
    let a: [NSAttributedString.Key: Any] = [
        NSAttributedString.Key(kCTFontAttributeName as String): CTFontCreateWithName(font as CFString, size, nil),
        NSAttributedString.Key(kCTForegroundColorAttributeName as String): color(ink)]
    let value = NSAttributedString(string: s, attributes: a)
    context.textPosition = CGPoint(x: x, y: height-y-size)
    CTLineDraw(CTLineCreateWithAttributedString(value), context)
}
func path(_ points: [(CGFloat, CGFloat)], _ ink: String = "#8aa5c4", _ arrow: Bool = false) {
    context.beginPath()
    for (i,p) in points.enumerated() {
        let q = CGPoint(x:p.0,y:height-p.1)
        if i == 0 {context.move(to:q)} else {context.addLine(to:q)}
    }
    context.setStrokeColor(color(ink));context.setLineWidth(1.4);context.strokePath()
    if arrow, points.count > 1 {
        let b = points.last!, a = points[points.count-2]
        let dx = b.0 == a.0 ? CGFloat(0) : (b.0 > a.0 ? CGFloat(1) : CGFloat(-1))
        let dy = b.1 == a.1 ? CGFloat(0) : (b.1 > a.1 ? CGFloat(1) : CGFloat(-1))
        path([(b.0-dx*9-dy*4,b.1-dy*9+dx*4),b,(b.0-dx*9+dy*4,b.1-dy*9-dx*4)],ink)
    }
}
let numbers = NumberFormatter()
numbers.numberStyle = .decimal
func num(_ v: Any?) -> String { numbers.string(from: (v as? NSNumber) ?? 0)! }
func mib(_ v: Any?) -> String { String(format:"%.2f MiB", ((v as? NSNumber)?.doubleValue ?? 0)/1048576) }
let iso = ISO8601DateFormatter()
iso.formatOptions = [.withInternetDateTime,.withFractionalSeconds]
func date(_ s: Any?) -> Date {
    let v = s as? String ?? ""
    if let d = iso.date(from:v) {return d}
    let plain = ISO8601DateFormatter()
    return plain.date(from:v) ?? Date(timeIntervalSince1970:0)
}
func stamp(_ s: Any?, _ format: String = "dd MMM yyyy · HH:mm 'IST'") -> String {
    let f = DateFormatter();f.timeZone=TimeZone(identifier:"Asia/Kolkata");f.dateFormat=format
    return f.string(from: date(s))
}
func top(_ schema: Bool) {
    rect(0,0,width,height,bg)
    rect(44,28,34,34,"#183a43",8);text("DB",50,35,17,cyan,"Menlo-Bold")
    text("ESP32 DNS Sinkhole",91,34,17,fg,"HelveticaNeue-Medium");text("/ PostgreSQL",270,37,13,muted)
    text(schema ? "RELATIONSHIPS" : "QUERY RESULTS",1325,37,12,cyan,"Menlo")
    path([(44,80),(1556,80)],lineColor)
    text(schema ? "STORAGE ARCHITECTURE" : "EVENT LEDGER",44,106,11,cyan,"Menlo")
    text(schema ? "Inside the DNS telemetry database" : "DNS decisions, stored and traceable",44,126,35,fg,"HelveticaNeue-Medium")
    text(schema ? "Device identity, idempotent batches, query outcomes and OTA state." : "Real event records and exact row counts from the retained trial data.",44,177,15,muted)
    text("Real PostgreSQL snapshot",1250,113,13,green)
    text(stamp(data["snapshot_at"]),1250,138,12,muted)
    text("Identifiers aliased · browsing domains hidden",1250,161,11,muted)
}
func stat(_ x: CGFloat, _ value: String, _ title: String, _ note: String) {
    rect(x,222,367,105,panel,10,lineColor)
    text(title,x+18,236,12,muted)
    text(value,x+18,256,31,fg,"HelveticaNeue-Medium")
    text(note,x+18,301,11,muted)
}
typealias Field = (String,String,String)
func entity(_ name: String, _ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ fields: [Field], _ note: String = "") {
    let h = CGFloat(48+fields.count*26+(note.isEmpty ? 10 : 37))
    rect(x,y,w,h,panel,9,"#3a4b65")
    rect(x+1,y+1,w-2,41,"#19273b",8)
    text(name,x+14,y+12,14,fg,"Menlo-Bold")
    text(num(counts[name])+" rows",x+w-99,y+15,11,muted,"Menlo")
    for (i,f) in fields.enumerated() {
        let fy = y+51+CGFloat(i*26)
        text(f.0,x+14,fy+1,10,f.0=="FK" ? purple : cyan,"Menlo")
        text(f.1,x+43,fy,12,fg,"Menlo")
        if !f.2.isEmpty {text(f.2,x+w-94,fy+1,11,muted,"Menlo")}
    }
    if !note.isEmpty {
        path([(x,y+h-31),(x+w,y+h-31)],lineColor)
        text(note,x+14,y+h-23,10,muted,"Menlo")
    }
}
func schema() {
    top(true)
    stat(44,num(counts["dns_events"]),"DNS events stored",num(stats["domains"])+" distinct domains")
    stat(425,num(counts["telemetry_batches"]),"Telemetry batches","unique per device + boot + sequence")
    stat(806,num(counts["client_counter_snapshots"]),"Client snapshots",num(stats["clients"])+" distinct client addresses")
    stat(1187,mib(data["storage_bytes"]),"Database tables + indexes","5 application tables · 4 Grafana views")
    rect(44,348,1512,624,panel,12,lineColor)
    text("Relational model",64,366,15,fg,"HelveticaNeue-Medium")
    text("PK Primary key     FK Foreign key     1 → N relationship     Selected columns shown",780,369,11,muted,"Menlo")
    path([(44,401),(1556,401)],lineColor)
    // All five arrows below correspond to declared PostgreSQL foreign keys.
    path([(484,558),(541,558),(541,568),(592,568)],"#8aa5c4",true)
    text("1",497,540,11,muted);text("N",572,548,11,muted)
    path([(1007,568),(1042,568),(1042,503),(1090,503)],"#8aa5c4",true)
    text("1",1016,549,11,muted);text("N",1071,484,11,muted)
    path([(1007,654),(1055,654),(1055,760),(1090,760)],"#8aa5c4",true)
    text("1",1016,635,11,muted);text("N",1071,741,11,muted)
    path([(145,499),(145,427),(1186,427),(1186,446)],"#8aa5c4",true)
    text("device_id · 1 → N",630,409,11,muted,"Menlo")
    path([(484,625),(530,625),(530,778),(1020,778),(1020,850),(1090,850)],"#8aa5c4",true)
    text("device_id · 1 → N",630,781,11,muted,"Menlo")
    entity("devices",76,499,408,[
        ("PK","device_id","text"),("","firmware_version","text"),("","blocklist_version","text"),("","last_seen_at","timestamptz")])
    entity("telemetry_batches",592,499,415,[
        ("PK","id","bigint"),("FK","device_id","text"),("","boot_id","text"),("","batch_sequence","bigint"),("","captured_at","timestamptz"),("","telemetry_dropped","bigint"),("","telemetry_upload_failures","bigint")],
        "UNIQUE (device_id, boot_id, batch_sequence)")
    entity("dns_events",1090,446,434,[
        ("PK","id","bigint"),("FK","batch_id","bigint"),("FK","device_id","text"),("","domain / action / outcome","text"),("","occurred_at","timestamptz"),("","upstream_latency_us","integer")],
        "UNIQUE (device_id, boot_id, batch_sequence, event_index)")
    entity("client_counter_snapshots",1090,714,434,[
        ("PK","id","bigint"),("FK","batch_id","bigint"),("FK","device_id","text"),("","client_ip","inet"),("","queries / blocked / forwarded","bigint")],
        "UNIQUE (batch_id, client_ip)")
    entity("blocklist_update_status",76,805,408,[
        ("PK","device_id + request_id","text"),("","stage / payload_crc32","text"),("","entry_count","bigint")])
    text("GRAFANA VIEWS ← dns_events",592,817,11,cyan,"Menlo")
    let views = data["views"] as! [String]
    for (i,v) in views.enumerated() {text(v,592,841+CGFloat(i*23),12,fg,"Menlo")}
    text("HTTPS batches → PostgreSQL events → SQL views → Grafana",44,991,12,muted)
    text("Update status uses a composite primary key. Migration history is omitted from the diagram.",44,1014,11,muted)
}
func ledger() {
    top(false)
    stat(44,num(counts["dns_events"]),"Stored DNS events","all retained events")
    stat(425,num(stats["blocked"]),"Blocked decisions","recorded action = blocked")
    stat(806,num(stats["forwarded"]),"Forwarded decisions","recorded action = forwarded")
    stat(1187,num(counts["telemetry_batches"]),"Stored telemetry batches","retried batches deduplicated")
    rect(44,348,1060,608,panel,12,lineColor)
    text("public.dns_events",64,368,15,fg,"Menlo-Bold")
    text("Latest 8 rows · ID descending",844,371,12,muted)
    rect(45,400,1058,42,"#142035")
    let xs: [CGFloat] = [64,145,254,360,745,866,957]
    for (i,s) in ["ID","Time · IST","Client","Domain","Action","RCODE","Latency"].enumerated(){text(s,xs[i],414,12,muted)}
    for (i,r) in samples.enumerated() {
        let y = CGFloat(448+i*49)
        if i > 0 {path([(45,y-7),(1103,y-7)],"#223047")}
        let action = r["action"] as! String
        let domain = r["domain"] as! String
        let shown = domain.count > 43 ? String(domain.prefix(40))+"…" : domain
        text(num(r["id"]),xs[0],y+8,12,fg,"Menlo")
        text(stamp(r["occurred_at"],"HH:mm:ss"),xs[1],y+8,12,fg,"Menlo")
        text(r["client"] as! String,xs[2],y+8,12)
        text(shown,xs[3],y+8,12,fg,"Menlo")
        rect(xs[4]-4,y+2,95,29,action=="blocked" ? "#163c32" : "#18384d",5)
        text(action,xs[4]+4,y+8,11,action=="blocked" ? green : "#8dd7ff")
        text(r["response_code"] is NSNull ? "—" : String(describing:r["response_code"]!),xs[5]+12,y+8,12,fg,"Menlo")
        text((r["latency_ms"] as? NSNumber).map { String(format:"%.2f ms",$0.doubleValue) } ?? "—",xs[6],y+8,12,fg,"Menlo")
    }
    path([(44,844),(1104,844)],lineColor)
    text("Actual rows · Identifiers aliased · — indicates no upstream latency measurement.",64,855,11,muted)
    text("SOURCE QUERY · read-only snapshot · sanitized on export",64,883,11,cyan,"Menlo")
    text("SELECT id, occurred_at, client_ip, domain, action,",64,904,13,fg,"Menlo")
    text("       response_code, upstream_latency_us FROM dns_events ORDER BY id DESC LIMIT 8;",64,925,12,fg,"Menlo")
    rect(1122,348,434,414,panel,12,lineColor)
    text("Stored records",1142,368,15,fg,"HelveticaNeue-Medium")
    text("Tables + indexes",1420,371,11,muted)
    path([(1122,400),(1556,400)],lineColor)
    let names = ["dns_events","telemetry_batches","client_counter_snapshots","devices","blocklist_update_status"]
    let maximum = tables.map{($0["bytes"] as! NSNumber).doubleValue}.max()!
    for (i,name) in names.enumerated() {
        let table = tables.first{$0["name"] as? String == name}!
        let bytes = (table["bytes"] as! NSNumber).doubleValue, y = CGFloat(411+i*69)
        text(name,1142,y,12,fg,"Menlo")
        text(num(counts[name]),1482,y,12,fg,"Menlo")
        rect(1142,y+24,394,4,"#233148",2)
        rect(1142,y+24,max(2,394*bytes/maximum),4,cyan,2)
        text("rows",1142,y+36,10,muted)
        text(mib(bytes),1453,y+36,10,muted)
    }
    rect(1122,780,434,176,panel,12,lineColor)
    text("ESP32 blocklist status",1142,798,15,fg,"HelveticaNeue-Medium")
    text(status?["stage"] as? String ?? "—",1490,802,12,green)
    text("Validated hashes on flash",1142,837,12,muted)
    text(num(status?["entries"]),1142,859,31,fg,"HelveticaNeue-Medium")
    text("Last reported "+stamp(status?["updated_at"]),1142,914,11,muted)
    text("Full retained database · "+stamp(stats["from"])+" → "+stamp(stats["to"]),44,984,12,muted)
    text("Snapshot only · refresh with python3 tools/export_database_visuals.py --images",44,1009,11,muted,"Menlo")
}
for (name,draw) in [("database-schema",schema),("database-records",ledger)] {
    context = CGContext(data:nil,width:Int(width*scale),height:Int(height*scale),bitsPerComponent:8,bytesPerRow:0,space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue)!
    context.scaleBy(x:scale,y:scale)
    draw()
    let image = context.makeImage()!
    let url = root.appendingPathComponent(name+".png")
    let dest = CGImageDestinationCreateWithURL(url as CFURL,"public.png" as CFString,1,nil)!
    CGImageDestinationAddImage(dest,image,nil)
    if !CGImageDestinationFinalize(dest){fatalError("Could not write image")}
    print(url.path)
}
