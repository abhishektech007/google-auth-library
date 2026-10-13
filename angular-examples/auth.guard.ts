/**
 * =============================================================================
 * Angular Route Guard: AuthGuard
 * File: auth.guard.ts
 * Purpose: Protects private routes from unauthenticated access.
 * =============================================================================
 */

import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { GoogleAuthService } from './google-auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(GoogleAuthService);
  const router = inject(Router);

  if (authService.getToken()) {
    return true;
  }

  // Not authenticated, redirect to login page with returnUrl query parameter
  router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
  return false;
};
