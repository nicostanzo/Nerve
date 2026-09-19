export default async function handler(req, res) {
  // Only accept POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // Security: only accept requests from our Middleware (using the secret)
  const authHeader = req.headers['authorization'];
  if (authHeader !== `Bearer ${process.env.WAF_SECRET}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { ip, durationHours = 24 } = req.body;
  
  if (!ip || ip === '0.0.0.0' || ip === 'unknown') {
    return res.status(400).json({ error: 'Valid IP address is required' });
  }

  const teamId = process.env.TEAM_ID || 'team_xtBLFiWiMH9OK9GcOoTOryNA';
  const edgeConfigId = process.env.EDGE_CONFIG_ID || 'ecfg_alubj5dumqerwdpyozhkwjm1qzpb';
  const token = process.env.VERCEL_API_TOKEN;

  // Calculate when the ban expires
  const unbanDate = new Date(Date.now() + durationHours * 3600 * 1000).toISOString();

  try {
    // 1. Fetch current banned IPs to preserve existing bans
    let currentBanned = {};
    try {
      const getUrl = `https://api.vercel.com/v1/edge-config/${edgeConfigId}/item/waf_banned_ips?teamId=${teamId}`;
      const getRes = await fetch(getUrl, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (getRes.ok) {
        const item = await getRes.json();
        // Handle both direct dictionary and Vercel item envelope
        currentBanned = (item && typeof item === 'object' && item.value && typeof item.value === 'object') 
          ? item.value 
          : (typeof item === 'object' && !item.key ? item : {});
      }
    } catch (e) {
      console.warn("Could not fetch existing bans, creating fresh dictionary", e);
    }

    currentBanned[ip] = unbanDate;

    // 2. Write updated banlist back to Edge Config via Vercel REST API
    const vercelApiUrl = `https://api.vercel.com/v1/edge-config/${edgeConfigId}/items?teamId=${teamId}`;
    const patchRes = await fetch(vercelApiUrl, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        items: [
          {
            operation: 'upsert',
            key: 'waf_banned_ips',
            value: currentBanned
          }
        ]
      })
    });

    if (!patchRes.ok) {
      const errorData = await patchRes.text();
      console.error("Vercel API Error:", errorData);
      return res.status(500).json({ error: 'Failed to update Edge Config', details: errorData });
    }

    return res.status(200).json({ success: true, banned: ip, until: unbanDate, totalBanned: Object.keys(currentBanned).length });
  } catch (error) {
    console.error("Handler Error:", error);
    return res.status(500).json({ error: 'Internal Server Error', message: error.message });
  }
}
