// import { Routes } from '@angular/router';

// export const routes: Routes = [];


import { Routes } from '@angular/router';
import { LoginComponent } from './login/login.component';
import { AdminPanelComponent } from './admin-panel/admin-panel.component';
import { TwoFactorComponent } from './two-factor/two-factor.component';

export const routes: Routes = [
  { path: 'login', component: LoginComponent }, // Maps to craftysogo.com/login locally
  { path: 'two-factor', component: TwoFactorComponent },
  { path: 'admin-panel', component: AdminPanelComponent },
  { path: '', redirectTo: '/login', pathMatch: 'full' },
];