'use strict';
require("dotenv").config();
const express = require('express');
const app = express();
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const helmet = require('helmet');
const geoip = require('geoip-lite');
const rateLimit = require('express-rate-limit');
const { facebook, capcut, tiktok, threads, instagram, douyin, pinterest, zingmp3, soundcloud, nettruyen, blogtruyen, nhaccuatoi } = require('./scraper/media.js');
const config = require("./config.json");
const { stories } = require('./scraper/stories.js');
const http = require('http');
const url = require('url');
const { spawn } = require('child_process');
const allowedCountries = ['VN', 'SG', 'US', 'NL'];

function isIpAllowed(ip) {
  const geo = geoip.lookup(ip);
  return geo && allowedCountries.includes(geo.country);
}

app.use((req, res, next) => {
  const ip = req.ip.replace(/^::ffff:/, '');
  if (isIpAllowed(ip)) {
    console.log(`IP Are Allowed: ${ip} - ${geoip.lookup(ip).country}`);
    next(); 
  } else {
    res.status(404).sendFile(`${__dirname}/public/blocked.html`);
    console.log(`IP Is Blocked: ${ip} - ${geoip.lookup(ip).country}`);
  }
});

const filesToCreate = ['banned_ips.txt', 'blocked_ips.txt'];
filesToCreate.forEach((file) => {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, '');
  }
});

const limiter = rateLimit({
  windowMs: 30 * 1000, 
  max: 10, 
  delayMs: 0, 
  handler: (req, res) => {
    const ip = req.ip;
    const blockTime = 30 * 1000;
    const banList = fs.readFileSync('banned_ips.txt', 'utf8').split('\n');
    if (banList.includes(ip)) {
      res.status(404).sendFile(path.join(__dirname, 'public/blocked.html'));
    } else {
      const blockedIps = new Set(fs.readFileSync('blocked_ips.txt', 'utf8').split('\n'));
      if (blockedIps.has(ip)) {
        res.status(429).send('Too Many Requests');
      } else {
        blockedIps.add(ip);
        fs.writeFileSync('blocked_ips.txt', Array.from(blockedIps).join('\n'));
        setTimeout(() => {
          blockedIps.delete(ip);
          fs.writeFileSync('blocked_ips.txt', Array.from(blockedIps).join('\n'));
        }, blockTime);
        res.status(429).send('Too Many Requests');
      }
    }
  },
});

const bannedIps = new Set(fs.readFileSync('banned_ips.txt', 'utf8').split('\n'));

app.use((req, res, next) => {
  const ip = req.ip;
  if (bannedIps.has(ip)) {
    res.status(404).sendFile(`${__dirname}/public/blocked.html`);
  } else {
    next();
  }
});

const headers = {
    "sec-fetch-user": "?1",
    "sec-ch-ua-mobile": "?0",
    "sec-fetch-site": "none",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "cache-control": "max-age=0",
    "authority": "www.facebook.com",
    "upgrade-insecure-requests": "1",
    "accept-language": "en-GB,en;q=0.9,tr-TR;q=0.8,tr;q=0.7,en-US;q=0.6",
    "sec-ch-ua": '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "cookie": config.cookie
};
const chuyen_doi_ten_mien = async (url) => {
  return url.replace(/d\.facebook\.com|www\.facebook\.com|m\.facebook\.com|mbasic\.facebook\.com/, 'www.facebook.com');
};
function isUrlValid(link) {
        var res = link.match(/(http(s)?:\/\/.)?(www\.)?(facebook|fb)\.(com|watch)\/([-a-zA-Z0-9@:%_+.~#?&//=]+)/);
        return res !== null; 
};
async function bypassUrl(url) {
  try {
    let apiUrl, publisherUrl;

    if (url.includes('traffic123')) {
      apiUrl = 'https://traffic123.net/que?q=status,azauth,q,t,z&filter=connection';
      publisherUrl = `https://traffic123.net/publisher`;
    } else if (url.includes('link68')) {
      apiUrl = 'https://link68.net/que?q=status,azauth,q,t,z&filter=connection';
      publisherUrl = `https://link68.net/publisher`;
    } else if (url.includes('laymangay')) {
      apiUrl = 'https://laymangay.com/que?q=status,azauth,q,t,z&filter=connection';
      publisherUrl = `https://laymangay.com/publisher`;
    } else if (url.includes('linkvertise')) {
      apiUrl = `https://api.bypass.vip/bypass?url=${encodeURIComponent(url)}`;
      const apiResponse = await axios.get(apiUrl);
      return apiResponse.data;
    } else {
      throw new Error('Unsupported URL domain');
    }

    const response = await axios.get(apiUrl);
    const { azauth, q, t } = response.data;

    const publisherResponse = await axios.get(`${publisherUrl}?azauth=${azauth}&q=${q}&t=${t}&opa=123&z=${encodeURIComponent(url)}`);
    const { password } = publisherResponse.data;

    return { password };
  } catch (error) {
    throw new Error(`Error bypassing URL: ${error.message}`);
  }
}
const notesDir = path.join(__dirname, 'notes');
if (!fs.existsSync(notesDir)) {
    fs.mkdirSync(notesDir);
}
app.use(express.static('public'));
app.use(helmet());
app.use(limiter);
app.use(express.json({ limit: '1mb' }));
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.set('json spaces', 4);
app.post('/api/save', (req, res) => {
  const { content } = req.body;

  const timestamp = Date.now().toString();
  const hash = crypto.createHash('sha256').update(timestamp).digest('hex');
  const filename = hash;

  const filePath = path.join(notesDir, filename);

  fs.writeFile(filePath, content, (err) => {
    if (err) {
      console.error('Error saving note:', err);
      res.status(500).json({ error: 'Error saving note' });
    } else {
      const rawUrl = `/raw/${filename}`;
      res.json({ rawUrl });
    }
  });
});
app.get('/raw/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.join(notesDir, filename);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      console.error('Error retrieving note:', err);
      res.status(404).json({ error: 'Note not found' });
    } else {
      res.setHeader('Content-Type', 'text/plain');
      res.send(data);
    }
  });
});
app.get('/api/bypass', async (req, res) => {
  const url = req.query.url;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  try {
    const result = await bypassUrl(url);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.get('/api/tiktok/buffview', async (req, res) => {
  const url = req.query.url;
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    const pythonProcess = spawn('python3', ['data/viewtik.py', url]);

    let output = '';
    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
      console.error(`[TikTok Viewbot] Error: ${data.toString().trim()}`);
    });

    pythonProcess.on('close', (code) => {
      if (code === 0) {
        return res.json({ message: `TikTok Viewbot finished with URL ${url}` });
      } else {
        console.error(`[TikTok Viewbot] Failed with code ${code}`);
        return res.status(500).json({ error: `TikTok Viewbot failed with URL ${url}` });
      }
    });

    setTimeout(() => {
      pythonProcess.kill();
    }, 10 * 60 * 1000); // 10 minutes timeout

    return res.json({ message: `Running TikTok Viewbot 200 views for URL ${url}` });
  } catch (error) {
    console.error(`[TikTok Viewbot] Error: ${error.message}`);
    return res.status(500).json({ error: `TikTok Viewbot failed with URL ${url}` });
  }
});
app.get('/api/bank/info', async (req, res) => {
  const { bank, stk } = req.query;

  if (!bank || !stk) {
    return res.status(400).json({ error: 'Ngan hang and STK are required' });
  }

  try {
    const bankInfoResponse = await axios.get('https://api.vietqr.io/v2/banks');
    const banks = bankInfoResponse.data.data;

    const bankInfo = banks.find(b => b.shortName === bank || b.code === bank);

    if (!bankInfo) {
      return res.status(400).json({ error: 'Invalid ngan hang' });
    }

    const bankCode = bankInfo.bin;

    const apiKeys = [
      { apiKey: '8e3b949a-ec65-4d5a-88a5-7910e6f879a5', clientId: '043a18b1-d729-462d-944b-45ede54e2e6a' },
      { apiKey: '13f2cdc3-1e12-4396-af4d-e87990df1c04', clientId: 'baf586f1-aa63-4275-854d-c44874bd71f7' },
      { apiKey: '1b6261ad-f1b8-497f-a09e-16d063722793', clientId: '3e162c6e-3d0a-44cf-9414-38e6d9683c25' },
      { apiKey: 'f6849cc5-6285-499c-a93f-db3808552c0a', clientId: 'c09d96b0-fb84-46ae-a305-50dc517b3f46' },
    ];

    for (const { apiKey, clientId } of apiKeys) {
      try {
        const data = JSON.stringify({
          bin: bankCode,
          accountNumber: stk
        });

        const config = {
          method: 'post',
          url: 'https://api.vietqr.io/v2/lookup',
          headers: { 
            'x-client-id': clientId, 
            'x-api-key': apiKey, 
            'Content-Type': 'application/json',
          },
          data: data
        };

        const lookupResponse = await axios(config);

        if (lookupResponse.data) {
          return res.json({ stk: stk, bank: bankCode, name: lookupResponse.data.data.accountName });
        }
      } catch (error) {
        console.error(`Error fetching data:`, error);
      }
    }

    return res.status(404).json({ error: 'No data returned' });
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Error fetching data' });
  }
});
app.get('/api/openai/gpt-4', async (req, res) => {
  var q = req.query.q;
  if (!q) {
    res.json({ error: "TEXT ?" });
    return;
  }
  try {
    const resp = (await axios.get(`https://hercai.onrender.com/v3/hercai?question=${q}`)).data;
    if (resp) {
      res.json(resp);
    } else {
      return res.status(404).json({ error: 'No data returned' });
    }
  } catch (error) {
       console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Error fetching data' });
  }
});
app.get('/api/down/media', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const link = await chuyen_doi_ten_mien(url);
    let modifiedLink = link;

    if (link.includes('facebook.com/story.php')) {
      modifiedLink += (req.query.id ? `&id=${req.query.id}` : '');
      modifiedLink += (req.query.story_fbid ? `&story_fbid=${req.query.story_fbid}` : '');
    }

    const platforms = {
      facebook: { regex: /facebook|fb/, func: facebook },
      tiktok: { regex: /tiktok/, func: tiktok },
      douyin: { regex: /douyin/, func: douyin },
      soundcloud: { regex: /soundcloud/, func: soundcloud },
      nhaccuatoi: { regex: /nhaccuatoi/, func: nhaccuatoi },
      blogtruyen: { regex: /blogtruyen/, func: blogtruyen },
      nettruyen: { regex: /nettruyen/, func: nettruyen },
      instagram: { regex: /instagram|ig/, func: instagram },
      pinterest: { regex: /pinterest|pin/, func: pinterest },
      threads: { regex: /threads/, func: threads },
      zingmp3: { regex: /zingmp3/, func: zingmp3 },
      capcut: { regex: /capcut/, func: capcut }
    };

    for (const platform in platforms) {
      if (platforms[platform].regex.test(modifiedLink)) {
        const resp = await platforms[platform].func(modifiedLink);
        if (resp) {
          return res.json(resp);
        }
      }
    }

    return res.status(404).json({ error: 'No data returned' });
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Error fetching data' });
  }
});
app.get('/api/facebook/stories', async (req, res) => {
var link = req.query.url;

  if (!link) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    link = await chuyen_doi_ten_mien(link);
    
    const resp = await stories(link);
    if (resp) {
      res.json(resp);
    } else {
      return res.status(404).json({ error: 'No data returned' });
    }
  } catch (error) {
       console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Error fetching data' });
  }
});
app.get('/api/facebook/getid', async (req, res) => {
let link = req.query.url;
let url = link;
if (link.includes('facebook.com/story.php')) {
  url += (req.query.id ? `&id=${req.query.id}` : '');
  url += (req.query.story_fbid ? `&story_fbid=${req.query.story_fbid}` : '');
}
    
    if (!link) res.json({ error: "Vui lòng nhập link facebook cần get id" });
    if (!isUrlValid(link)) res.json({ error: "Vui lòng nhập link facebook hợp lệ !" });
const linkShareRegex = /^https:\/\/www\.facebook\.com\/share\/(.*)/;
const storyMatch = url.match(/facebook\.com\/story\.php\?(?:id=([a-zA-Z0-9]+)&story_fbid=([a-zA-Z0-9]+)|story_fbid=([a-zA-Z0-9]+)&id=([a-zA-Z0-9]+))/);
const postMatch = link.match(/facebook\.com\/([\d\w\.]+)\/(posts|videos)\/(?:.*\/)?([^/?&]+)/);
const storiesMatch = link.match(/facebook\.com\/stories\/([-a-zA-Z0-9@:%_+.~#?&//=]+)\/([-a-zA-Z0-9@:%_+.~#?&//=]+)/);
const photoRegex = /facebook\.com\/photo\.php\?fbid=([-a-zA-Z0-9@:%_+.~#?//=]+)/;
const groupsMatch = link.match(/facebook\.com\/groups\/([-a-zA-Z0-9@:%_+.~#?&//=]+)\/permalink\/([-a-zA-Z0-9@:%_+.~#?&//=]+)/);
const reelMatch = link.match(/facebook\.com\/reel\/([-a-zA-Z0-9@:%_+.~#?&//=]+)/);
    if (linkShareRegex.test(link)) {
        try {  	
            const response = await axios.get(link);
const responseData = decodeURIComponent(response.request.res.responseUrl).replace(/https:\/\/(?:www\.)?facebook\.com\/(?:login|login\.php)\/?\?next=/, '');
const new_url = responseData.replace("m.facebook.com", "www.facebook.com");
const urlParts = new_url.split('?mibextid=')[0];
            const reelResult = urlParts.match(/facebook\.com\/reel\/([-a-zA-Z0-9@:%_+.~#?&//=]+)/);
        const postResult = urlParts.match(/facebook\.com\/([\d\w\.]+)\/(posts|videos)\/(?:.*\/)?([^/?&]+)/);
            const photoResult = urlParts.match(/facebook\.com\/photo\.php\?fbid=([-a-zA-Z0-9@:%_+.~#?//=]+)/);
            const storyResult = urlParts.match(/facebook\.com\/story\.php\?(?:id=([a-zA-Z0-9]+)&story_fbid=([a-zA-Z0-9]+)|story_fbid=([a-zA-Z0-9]+)&id=([a-zA-Z0-9]+))/);            
            const storiesResult = responseData.match(/facebook\.com\/stories\/([-a-zA-Z0-9@:%_+.~#?&//=]+)\/([-a-zA-Z0-9@:%_+.~#?&//=]+)/);
const groupsResult = responseData.match(/facebook\.com\/groups\/([-a-zA-Z0-9@:%_+.~#?&//=]+)\/permalink\/([-a-zA-Z0-9@:%_+.~#?&//=]+)/);
if (storyResult) {
    const ssdf = await axios.get(urlParts, { headers });
    const kfkfk = ssdf.data;
    const regexMatches = {
      storyMatch: kfkfk.match(/"story_fbid":"(.*?)","id":"(.*?)"/),
    };
    const getUserId = (await axios.get(`https://fbuid.mktsoftware.net/api/v1/fbprofile?url=https://www.facebook.com/groups/${regexMatches.storyMatch[2]}`)).data;
res.json({
  type: "story",
  username: getUserId.uid,
  id: regexMatches.storyMatch[1]
});
}
             if (storiesResult) {
    const idParts = urlParts.split('/');
    const id = idParts[4];
    const id_stories = idParts[5];
    res.json({
        type: "stories",
        url: urlParts,
        username: id,
        id: id_stories
             });
            }
             if (groupsResult) {
                const urlParts = responseData.split('/');
                const username = urlParts[4];
                const postId = urlParts[6];
                const getUserId = (await axios.get(`https://fbuid.mktsoftware.net/api/v1/fbprofile?url=https://www.facebook.com/groups/${username}`)).data;
                res.json({
                	type: "post",
                    username: getUserId.uid || null,
                    id: postId
                });
            }
            if (postResult) {
   	 const username = postResult[1];
        const postId = postResult[3].split("?")[0].replace("/", "");
        const getUserId = (await axios.get(`https://fbuid.mktsoftware.net/api/v1/fbprofile?url=https://www.facebook.com/${username}`)).data;
            res.json({
            	type: "post",
                username: getUserId.uid || null,
                id: postId
            });
            }
            if (reelResult) {
        const postId = reelResult[1].split("?")[0].replace("/", "");
        res.json({
        	type: "reel",
            id: postId
        });
            }
            if (photoResult) {
        const postId = photoResult[1].split('&');
        res.json({
        	type: "photo",
            id: postId[0]
        });
            }
        } catch (error) {
            res.json({ error: "Không thể lấy UID từ URL Share." });
        }
        } else if  (postMatch) {
        const username = postMatch[1];
        const postId = postMatch[3].split("?")[0].replace("/", "");
        try {
            const getUserId = (await axios.get(`https://fbuid.mktsoftware.net/api/v1/fbprofile?url=https://www.facebook.com/${username}`)).data;
            res.json({
            	type: "post",
                username: getUserId.uid || null,
                id: postId
            });
        } catch (error) {
            res.json({ error: "Không thể lấy UID từ URL của người dùng." });
        }
    } else if (photoRegex.test(link)) {
        const postId = link.split('fbid=')[1].split('&')[0];
        res.json({
        	type: "photo",
            id: postId
        }); 
        } else if (storyMatch) {
const ssdf = await axios.get(url, { headers });
    const kfkfk = ssdf.data;
    const regexMatches = {
      storyMatch: kfkfk.match(/"story_fbid":"(.*?)","id":"(.*?)"/),
    };
    const getUserId = (await axios.get(`https://fbuid.mktsoftware.net/api/v1/fbprofile?url=https://www.facebook.com/groups/${regexMatches.storyMatch[2]}`)).data;
res.json({
  type: "story",
  username: getUserId.uid,
  id: regexMatches.storyMatch[1]
});
        } else if (reelMatch) {
        const postId = reelMatch[1].split("?")[0].replace("/", "");
        res.json({
        	type: "reel",
            id: postId
        });
 } else if (link.includes('fb.watch')) {
 	 const response = await axios.get(link);
      const responseData = decodeURIComponent(response.request.res.responseUrl);
const urlParts = responseData.replace(/https:\/\/(?:www\.)?facebook\.com\/(?:login|login\.php)\/?\?next=|https:\/\/m\.facebook\.com/, 'https://www.facebook.com');
      const spli = urlParts.split('/');
const idRegex = /\?v=([^&]+)/;
const match = urlParts.match(idRegex);
const postId2 = match && match[1];
        const getUserId = (await axios.get(`https://fbuid.mktsoftware.net/api/v1/fbprofile?url=https://www.facebook.com/${username}`)).data;
    res.json({
        type: 'watch',
        id: postId2
    });
   } else if (storiesMatch) {
    const urlParts = link.split('?mibextid=')[0];
    const idParts = urlParts.split('/');
    const id = idParts[4];
    const id_stories = idParts[5];
    res.json({
        type: "stories",
        url: urlParts,
        username: id,
        id: id_stories
             });
    } else if (groupsMatch) {
        const username = groupsMatch[1];
        const postId = groupsMatch[2].split("?")[0].replace("/", "");
        try {
            const getUserId = (await axios.get(`https://fbuid.mktsoftware.net/api/v1/fbprofile?url=https://www.facebook.com/groups/${username}`)).data;
            res.json({
            	type: "post",
                username: getUserId.uid || null,
                id: postId
            });
        } catch (error) {
            res.status(404).json({ error: "Không thể lấy UID từ URL của groups." });
        }
    } else {
        res.status(404).json({ error: "Liên kết không phải là bài đăng trên Facebook.", url: url });
    }
});
app.get('/server/image/anime', async (req, res) => {
  const url = 'https://waifu.im';
  const { data } = await axios.get(url);

  const $ = cheerio.load(data);
  const imageUrl = $('div.zoom img').last().attr('src');

  res.json({
      url: imageUrl
    });
});

app.use((error, req, res, next) => {
  res.status(error.status || 400).json({ message: error.message });
});

const servers = [
  { host: 'localhost', port: 3001 },
  { host: 'localhost', port: 3002 },
  { host: 'localhost', port: 3003 }
];

servers.forEach((server) => {
  const serverHttp = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`Server ${server.port} responding...\n`);
  });
  serverHttp.listen(server.port, () => {
    console.log(`Server listening on port ${server.port}`);
  });
});

const balancer = http.createServer((req, res) => {
const server = getNextServer();
const proxyReq = http.request({
    host: server.host,
    port: server.port,
    method: req.method,
    path: url.parse(req.url).path,
    headers: req.headers
  }, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  req.pipe(proxyReq);
});

let serverIndex = 0;
function getNextServer() {
  const server = servers[serverIndex];
  serverIndex = (serverIndex + 1) % servers.length;
  return server;
}

balancer.listen(3000, () => {
  console.log('Load balancer listening on port 3000');
});

app.use((req, res) => {
  const proxyReq = http.request({
    host: 'localhost',
    port: 3000,
    method: req.method,
    path: req.url,
    headers: req.headers
  }, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  req.pipe(proxyReq);
});

app.set('port', process.env.PORT || 80);

let version = 1;

fs.watch('public/index.html', () => {
  version++;
});

app.get('/', (req, res) => {
  const cacheKey = `index.html?v=${version}`;
  const cacheValue = cache.get(cacheKey);

  if (cacheValue) {
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(cacheValue);
  } else {
    const html = fs.readFileSync('public/index.html', 'utf8');
    cache.set(cacheKey, html);
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(html);
  }
});

app.listen(app.get('port'), () => {
  console.log(`\x1b[36mServer started on port ${app.get('port')}\x1b[0m`);
});