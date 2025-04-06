

import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-two-factor',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './two-factor.component.html', 
})
export class TwoFactorComponent {
  qrCode: string | null = null;
  userId: number | null = null;
  is2FASetup: boolean = false;
  token: string = '';

  constructor(private http: HttpClient, private router: Router) {
    const navigation = this.router.getCurrentNavigation();
    const state = navigation?.extras.state as { qrCode: string; userId: number; is2FASetup: boolean };
    if (state) {
      this.qrCode = state.qrCode || null;
      this.userId = state.userId || null;
      this.is2FASetup = state.is2FASetup || false;
    }
  }

  verify() {
    if (!this.userId || !this.token) {
      alert('Please enter a valid 2FA code');
      return;
    }
    this.http.post('http://localhost:3000/verify-2fa', { userId: this.userId, token: this.token }).subscribe({
      next: (res: any) => {
        if (res.success) {
          localStorage.setItem('role', res.role);
          this.router.navigate(['/admin-panel']);
        } else {
          alert('Invalid 2FA code');
        }
      },
      error: (err) => {
        console.error('2FA verification failed:', err);
        alert('2FA verification failed');
      },
    });
  }
}