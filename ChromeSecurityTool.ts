// ChromeSecurityTool.ts
import puppeteer, { Browser, LaunchOptions, Page } from 'puppeteer';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';

// Tipler ve Arayüzler
type ProxyConfig = { address: string; username?: string; password?: string };
type SecurityTestResult = { testType: string; payload: string; isVulnerable: boolean };
type ScanReport = { url: string; timestamp: string; results: SecurityTestResult[] };

class ChromeSecurityTool {
  private executablePath: string;
  private userDataDir: string = `./profiles/${uuidv4()}`; // Benzersiz profil
  private browser: Browser | null = null;
  private proxies: ProxyConfig[] = [];
  private currentProxyIndex: number = 0;

  constructor(platform: NodeJS.Platform = process.platform) {
    this.setPlatformPaths(platform);
    this.cleanupOldProfiles(); // Eski profilleri temizle
  }

  // Platforma özel yolları ayarla
  private setPlatformPaths(platform: NodeJS.Platform) {
    switch (platform) {
      case 'win32': this.executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'; break;
      case 'darwin': this.executablePath = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'; break;
      case 'linux': this.executablePath = '/usr/bin/google-chrome'; break;
      default: throw new Error('Unsupported platform');
    }
  }

  // Proxy listesi ekle
  public addProxies(proxies: ProxyConfig[]) {
    this.proxies = proxies;
  }

  // Rastgele User-Agent üret (Kütüphane bağımlılığı kaldırıldı)
  private generateUserAgent(): string {
    const agents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15'
    ];
    return agents[Math.floor(Math.random() * agents.length)];
  }

  // Tarayıcıyı başlat
  public async launchBrowser(options: LaunchOptions = { headless: true }) {
    const args: string[] = [
      `--user-data-dir=${this.userDataDir}`,
      '--no-sandbox',
      '--disable-web-security',
      `--user-agent=${this.generateUserAgent()}`
    ];

    // Proxy rotasyonu
    if (this.proxies.length > 0) {
      const proxy = this.proxies[this.currentProxyIndex % this.proxies.length];
      args.push(`--proxy-server=${proxy.address}`);
      if (proxy.username && proxy.password) args.push(`--proxy-auth=${proxy.username}:${proxy.password}`);
      this.currentProxyIndex++;
    }

    try {
      this.browser = await puppeteer.launch({ ...options, executablePath: this.executablePath, args });
    } catch (error) {
      throw new Error(`Browser launch failed: ${(error as Error).message}`);
    }
  }

  // Güvenlik taraması
  public async runSecurityScan(url: string): Promise<ScanReport> {
    if (!this.browser) throw new Error('Browser not launched!');
    const page = await this.browser.newPage();
    const report: ScanReport = { url, timestamp: new Date().toISOString(), results: [] };

    try {
      // XSS, SQLi, CSRF testleri
      report.results.push(...await this.testXSS(page, url));
      report.results.push(...await this.testSQLi(page, url));
      report.results.push(...await this.testCSRF(page, url));
    } catch (error) {
      console.error(`Scan failed for ${url}: ${(error as Error).message}`);
    } finally {
      await page.close();
      this.generateReport(report); // Rapor oluştur
    }
    return report;
  }

  // CSRF Testi (Yeni özellik)
  private async testCSRF(page: Page, url: string): Promise<SecurityTestResult[]> {
    await page.goto(url);
    const results: SecurityTestResult[] = [];
    // Anti-CSRF token kontrolü
    const csrfToken = await page.$eval('input[name="csrf_token"]', el => (el as HTMLInputElement).value);
    results.push({ testType: 'CSRF', payload: 'Token Check', isVulnerable: !csrfToken });
    return results;
  }

  // Rapor oluştur (JSON ve CSV)
  private generateReport(report: ScanReport) {
    const reportDir = './reports';
    if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });

    // JSON Rapor
    fs.writeFileSync(
      path.join(reportDir, `report_${Date.now()}.json`),
      JSON.stringify(report, null, 2)
    );

    // CSV Rapor
    const csvContent = [
      'Test Type,Payload,Is Vulnerable',
      ...report.results.map(r => `${r.testType},${r.payload},${r.isVulnerable}`)
    ].join('\n');
    fs.writeFileSync(path.join(reportDir, `report_${Date.now()}.csv`), csvContent);
  }

  // Eski profilleri temizle
  private cleanupOldProfiles() {
    const profilesDir = './profiles';
    if (fs.existsSync(profilesDir)) {
      fs.rmdirSync(profilesDir, { recursive: true });
    }
  }

  public async closeBrowser() {
    await this.browser?.close();
  }
}

export default ChromeSecurityTool;    
