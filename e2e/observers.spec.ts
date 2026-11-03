import { test, expect } from '@playwright/test';
import { boot, scan, NARROW } from './gate';
for (const narrow of [false, true]) {
test(`independent observers ${narrow ? 'phone' : 'desktop'}`, async ({ page }) => {
    test.setTimeout(180_000);
    if (narrow) await page.setViewportSize(NARROW);
    await boot(page, 'dark');
    const section = page.locator('#independent-observers');
    await section.getByRole('button', { name: 'Create / reset observer copies' }).click();
    const a = section.locator('[data-view="a"]'), b = section.locator('[data-view="b"]');
    await expect(a).toContainText('Curator: VALID'); await expect(b).toContainText('Curator: VALID');
    await scan(page, 'observer copies');
    await section.getByRole('checkbox').uncheck();
    await expect(b).toContainText('Curator: INVALID'); await expect(a).toContainText('Curator: VALID');
    await scan(page, 'independent owner trust');
    await section.getByRole('checkbox').check(); await expect(b).toContainText('Curator: VALID');
    await section.getByRole('button', { name: 'Issue Archivist’s revocation' }).click();
    await section.getByRole('button', { name: 'Send forged revocation to B' }).click();
    await expect(section.getByRole('status')).toContainText('rejected'); await expect(b).toContainText('Revocations received: none');
    await scan(page, 'forged revocation rejected');
    await section.getByRole('button', { name: 'Deliver to observer A' }).click();
    await expect(a).toContainText('Curator: INVALID'); await expect(b).toContainText('Curator: VALID');
    await scan(page, 'different received records');
    await section.getByRole('button', { name: 'Deliver to observer B' }).click();
    await expect(b).toContainText('Curator: INVALID');
    await scan(page, 'both received revocation');
});
}
