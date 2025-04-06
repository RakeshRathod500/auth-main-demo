

import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule],
  templateUrl: './login.component.html',
})
export class LoginComponent {
  username = '';
  password = '';

  constructor(private http: HttpClient, private router: Router) {}

  onLogin() {
    console.log('Login attempt from frontend:', { username: this.username, password: this.password });
    this.http.post('http://localhost:3000/login', { username: this.username, password: this.password }).subscribe({
      next: (res: any) => {
        console.log('Login response:', res);
        // If success is true (admin login), go directly to admin panel
        if (res.success) {
          console.log('Admin login successful, navigating to admin panel');
          localStorage.setItem('role', res.role);
          this.router.navigate(['/admin-panel']);
        }
        // Otherwise, proceed to 2FA (for users)
        else if (res.qrCode) {
          console.log('Non-admin first login, navigating to 2FA with QR code');
          this.router.navigate(['/two-factor'], { state: { qrCode: res.qrCode, userId: res.userId, is2FASetup: false } });
        } else if (res.is2FASetup) {
          console.log('Non-admin subsequent login, navigating to 2FA code entry');
          this.router.navigate(['/two-factor'], { state: { userId: res.userId, is2FASetup: true } });
        } else {
          console.error('Unexpected response from backend:', res);
          alert('Unexpected response from server');
        }
      },
      error: (err) => {
        console.error('Login failed with error:', err);
        alert('Login failed');
      },
    });
  }
}