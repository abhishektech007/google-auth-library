/**
 * =============================================================================
 * Angular Component: LoginComponent
 * File: login.component.ts
 * Purpose: Renders the Google Identity Services button container.
 * =============================================================================
 */

import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { GoogleAuthService } from './google-auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="auth-container">
      <div class="card">
        <h2>Enterprise Authentication</h2>
        <p>Sign in using your corporate or verified Google account</p>
        
        <!-- Google Identity Services Button Target -->
        <div id="googleSignInButton" class="google-btn-wrapper"></div>
      </div>
    </div>
  `,
  styles: [`
    .auth-container {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 80vh;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .card {
      background: #ffffff;
      padding: 2.5rem;
      border-radius: 12px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
      text-align: center;
      max-width: 400px;
      width: 100%;
    }
    .google-btn-wrapper {
      margin-top: 2rem;
      display: flex;
      justify-content: center;
    }
  `],
})
export class LoginComponent implements OnInit {
  private googleAuthService = inject(GoogleAuthService);

  ngOnInit(): void {
    // Initialize Google Button inside the container div
    this.googleAuthService.initializeGoogleSignIn('googleSignInButton');
  }
}
