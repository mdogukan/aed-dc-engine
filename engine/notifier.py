<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>AED-DC Engine | Canlı Tehdit Paneli</title>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }
        h1 { color: #58a6ff; font-size: 20px; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .status { color: #3fb950; font-weight: bold; margin-bottom: 15px; }
        .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        .panel { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #30363d; padding: 8px; text-align: left; font-size: 13px; }
        th { background-color: #21262d; color: #8b949e; }
        .badge-drop { background-color: #da3633; color: white; padding: 2px 6px; border-radius: 4px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>AED-DC Engine - Canlı Savunma ve Tecrit Paneli</h1>
    <div class="status" id="ws-status">● Sistem Yayınına Bağlanılıyor...</div>

    <div class="grid">
        <div class="panel">
            <h3>Canlı Yakalanan Saldırılar & Telemetri</h3>
            <table>
                <thead>
                    <tr>
                        <th>Zaman</th>
                        <th>Saldırgan IP</th>
                        <th>Port</th>
                        <th>Protokol</th>
                        <th>Çekirdek Eylemi</th>
                    </tr>
                </thead>
                <tbody id="attack-rows"></tbody>
            </table>
        </div>

        <div class="panel">
            <h3>Aktif nftables Tecritleri</h3>
            <table>
                <thead>
                    <tr>
                        <th>İzole Edilen IP</th>
                        <th>Durum</th>
                    </tr>
                </thead>
                <tbody id="isolation-rows"></tbody>
            </table>
        </div>
    </div>

    <script>
        const ws = new WebSocket(`ws://${location.host}/ws/live`);
        const statusEl = document.getElementById("ws-status");
        const attackRows = document.getElementById("attack-rows");
        const isolationRows = document.getElementById("isolation-rows");

        ws.onopen = () => {
            statusEl.innerText = "● Canlı Yayın Aktif - Çekirdek Dinlemede";
            statusEl.style.color = "#3fb950";
        };

        ws.onclose = () => {
            statusEl.innerText = "○ Yayın Bağlantısı Kesildi";
            statusEl.style.color = "#da3633";
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            // Yeni yakalanan saldırıyı tablonun en üstüne ekle
            const row = document.createElement("tr");
            row.innerHTML = `
                <td>${data.timestamp.split('T')[1].split('.')[0]}</td>
                <td><strong>${data.source_ip}</strong></td>
                <td>${data.target_port}</td>
                <td>${data.protocol}</td>
                <td><span class="badge-drop">nftables DROP</span></td>
            `;
            attackRows.prepend(row);

            // Sağdaki aktif tecrit listesine ekle
            const isoRow = document.createElement("tr");
            isoRow.innerHTML = `<td>${data.source_ip}</td><td><span class="badge-drop">DROP</span></td>`;
            isolationRows.prepend(isoRow);
        };
    </script>
</body>
</html>
