/**
 * =============================================================================
 * Angular Service: GoogleAuthService
 * File: google-auth.service.ts
 * Purpose: Handles Google Identity Services (GIS) One Tap / Sign-In Button
 *          initialization and backend token exchange with Express.
 * =============================================================================
 */

import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap, catchError, throwError } from 'rxjs';

export interface UserProfile {
  sub: string;
  email: string;
  name: string;
  picture: string;
  givenName?: string;
  familyName?: string;
}

export interface AuthResponse {
  success: boolean;
  message: string;
  token: string;
  user: UserProfile;
  expiresIn: string;
}

declare const google: any;

@Injectable({
  providedIn: 'root',
})
export class GoogleAuthService {
  private http = inject(HttpClient);
  private router = inject(Router);

  private readonly API_BASE = 'http://localhost:5000/api';
  private readonly GOOGLE_CLIENT_ID = 'your-google-client-id.apps.googleusercontent.com';
  private readonly TOKEN_KEY = 'auth_session_token';

  // Reactive state management using Angular Signals
  currentUser = signal<UserProfile | null>(null);
  isAuthenticated = signal<boolean>(false);

  constructor() {
    this.restoreSession();
  }

  /**
   * Initializes Google Identity Services (GIS) client.
   * Renders the official Google button into the provided HTML element ID.
   *
   * @param elementId DOM container element ID (e.g. 'google-btn')
   */
  initializeGoogleSignIn(elementId: string): void {
    if (typeof google === 'undefined') {
      console.error('Google Identity Services script not loaded. Include <script src="https://accounts.google.com/gsi/client" async defer></script> in index.html');
      return;
    }

    google.accounts.id.initialize({
      client_id: this.GOOGLE_CLIENT_ID,
      callback: (response: any) => this.handleCredentialResponse(response),
      auto_select: false,
      cancel_on_tap_outside: true,
    });

    const container = document.getElementById(elementId);
    if (container) {
      google.accounts.id.renderButton(container, {
        theme: 'outline',
        size: 'large',
        type: 'standard',
        shape: 'rectangular',
        text: 'signin_with',
        logo_alignment: 'left',
        width: 250,
      });
    }

    // Optional: Trigger Google One Tap prompt
    // google.accounts.id.prompt();
  }

  /**
   * Internal callback invoked upon successful user authentication in Google popup.
   *
   * @param response CredentialResponse containing raw Google ID token
   */
  private handleCredentialResponse(response: any): void {
    if (!response || !response.credential) {
      console.error('Invalid credential response received from Google.');
      return;
    }

    // Exchange Google ID Token with backend Express server
    this.verifyGoogleTokenOnBackend(response.credential).subscribe({
      next: (authRes) => {
        console.log('Successfully authenticated via backend custom JWT:', authRes.user.email);
        this.router.navigate(['/dashboard']);
      },
      error: (err) => {
        console.error('Backend verification failed:', err);
      },
    });
  }

  /**
   * Sends Google ID Token to the Express backend for cryptographic verification.
   *
   * @param credential Google JWT ID token string
   */
  verifyGoogleTokenOnBackend(credential: string): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.API_BASE}/auth/google`, { credential }).pipe(
      tap((res) => {
        if (res.token) {
          localStorage.setItem(this.TOKEN_KEY, res.token);
          this.currentUser.set(res.user);
          this.isAuthenticated.set(true);
        }
      }),
      catchError((error) => {
        this.logout();
        return throwError(() => error);
      })
    );
  }

  /**
   * Retrieves the stored internal session token.
   */
  getToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  /**
   * Restores existing user session on application reload.
   */
  private restoreSession(): void {
    const token = this.getToken();
    if (!token) return;

    this.http.get<{ authenticated: boolean; user: UserProfile }>(`${this.API_BASE}/auth/me`).subscribe({
      next: (res) => {
        if (res.authenticated && res.user) {
          this.currentUser.set(res.user);
          this.isAuthenticated.set(true);
        }
      },
      error: () => this.logout(),
    });
  }

  /**
   * Terminates active session on client and notifies backend.
   */
  logout(): void {
    localStorage.removeItem(this.TOKEN_KEY);
    this.currentUser.set(null);
    this.isAuthenticated.set(false);

    this.http.post(`${this.API_BASE}/auth/logout`, {}).subscribe({
      next: () => {},
      error: () => {},
    });

    if (typeof google !== 'undefined' && google.accounts && google.accounts.id) {
      google.accounts.id.disableAutoSelect();
    }

    this.router.navigate(['/login']);
  }
}
