import { test, expect } from '@playwright/test';
test('independent receipt, signature rejection and local trust remain visible', async ({ page }) => {
    await page.goto('/crypto-lab-web-of-trust/');
    const section = page.locator('#independent-observers');
    await section.getByRole('button', { name: 'Create / reset observer copies' }).click();
    const a = section.locator('[data-view="a"]'), b = section.locator('[data-view="b"]');
    await expect(a).toContainText('Curator: VALID'); await expect(b).toContainText('Curator: VALID');
    await section.getByRole('checkbox').uncheck();
    await expect(b).toContainText('Curator: INVALID'); await expect(a).toContainText('Curator: VALID');
    await section.getByRole('checkbox').check(); await expect(b).toContainText('Curator: VALID');
    await section.getByRole('button', { name: 'Issue Archivist’s revocation' }).click();
    await section.getByRole('button', { name: 'Send forged revocation to B' }).click();
    await expect(section.getByRole('status')).toContainText('rejected'); await expect(b).toContainText('Revocations received: none');
    await section.getByRole('button', { name: 'Deliver to observer A' }).click();
    await expect(a).toContainText('Curator: INVALID'); await expect(b).toContainText('Curator: VALID');
    await section.getByRole('button', { name: 'Deliver to observer B' }).click();
    await expect(b).toContainText('Curator: INVALID');
});
