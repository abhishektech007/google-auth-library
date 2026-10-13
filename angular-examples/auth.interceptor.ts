/**
 * =============================================================================
 * Angular HTTP Interceptor: AuthInterceptor
 * File: auth.interceptor.ts
 * Purpose: Automatically attaches Bearer session token to outgoing HTTP requests
 *          and catches HTTP 401/403 errors to trigger automatic redirect/logout.
 * =============================================================================
 */

import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { GoogleAuthService } from './google-auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(GoogleAuthService);
  const router = inject(Router);

  const token = authService.getToken();

  // Clone request with Authorization header if token is present
  const authReq = token
    ? req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
        },
      })
    : req;

  return next(authReq).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401 || error.status === 403) {
        console.warn('[AUTH INTERCEPTOR] Session invalid or expired. Redirecting to login.');
        authService.logout();
        router.navigate(['/login']);
      }
      return throwError(() => error);
    })
  );
};
