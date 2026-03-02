import { browser } from 'k6/browser';
import { sleep } from 'k6';
import exec from 'k6/execution';

// Per-step transaction tag: set at startTransaction, removed at endTransaction so all
// metrics (including browser_http_*) emitted in between get transaction=<name>.

export const options = {
  scenarios: {
    homepage: {
      executor: 'per-vu-iterations',
      exec: 'default',
      vus: 1,
      iterations: 1,
      options: {
        browser: {
          type: 'chromium',
        },
      },
    },
  },
  blockHostnames: [
    'apps.mypurecloud.com', '*.facebook.com', '*.facebook.net', '*.hotjar.com',
    'www.googletagmanager.com', '*.visualwebsiteoptimizer.com',
    '*.visualstudio.com', '*.monitor.azure.com', '*.braze.eu', '*.pages06.net', '*.applicationinsights.azure.com'
  ]
};
import { Trend } from 'k6/metrics';

const transactionStartTimes = {};
export const pages = new Trend('pages', true);

export function startTransaction(pageName) {
  transactionStartTimes[pageName] = Date.now();
  // Set transaction tag so all metrics (e.g. browser_http_*) emitted until endTransaction get transaction=<name>
  exec.vu.tags['transaction'] = pageName;
}

export function endTransaction(pageName) {
  if (transactionStartTimes[pageName]) {
    const start = transactionStartTimes[pageName];
    const end = Date.now();
    const rt = end - start;

    pages.add(rt, { page: pageName });

    delete transactionStartTimes[pageName];
  } else {
    console.log(`Transaction '${pageName}' was not started.`);
  }
  // Remove transaction tag so the next startTransaction sets its own
  // delete exec.vu.tags['transaction'];
}

export default async function() {
  const page = await browser.newPage();

  try {
  
    // sleep (10)
    await startTransaction("01_Homepage")
      await page.goto('https://webtv.delta.nl/', {waitUntil: 'load'});
      await page.waitForSelector('app-home .more_info');
    await endTransaction("01_Homepage")

    sleep(1)

    await startTransaction("02_Live")
      await page.locator('//a[contains(text(),"Live")]').click(),
      await page.waitForSelector('app-live-tv-overview .more_info');
    await endTransaction("02_Live")
    
    sleep(1)
    await startTransaction("03_TVGids")
      await page.locator('//a[contains(text(),"TV Gids")]').click(),
      (await page.waitForSelector('app-guide .selected.live img')).isVisible()
    await endTransaction("03_TVGids")

    sleep(1)
  } finally {
    page.close();
  }
}