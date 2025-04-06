
import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';

@Component({
  selector: 'app-admin-panel',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './admin-panel.component.html',
})
export class AdminPanelComponent {
  users: any[] = [];
  newUser = { username: '', password: '', role: 'user' }; 
  editUser: any = null; 
  showAddModal: boolean = false; // To show/hide the add user modal
  showEditModal: boolean = false; // To show/hide the edit user modal
  userRole: string | null = null; // To store the logged-in user's role

  constructor(private http: HttpClient, private router: Router) {
    // Retrieve the role from localStorage
    this.userRole = localStorage.getItem('role');
    this.loadUsers();
  }

  loadUsers() {
    this.http.get('http://localhost:3000/users').subscribe({
      next: (res: any) => {
        this.users = res;
      },
      error: (err) => {
        console.error('Failed to load users:', err);
      },
    });
  }

  openAddModal() {
    this.newUser = { username: '', password: '', role: 'user' }; 
    this.showAddModal = true;
  }

  closeAddModal() {
    this.showAddModal = false;
  }

  addUser() {
    this.http.post('http://localhost:3000/users', this.newUser).subscribe({
      next: () => {
        this.loadUsers();
        this.closeAddModal();
      },
      error: (err) => {
        console.error('Failed to add user:', err);
      },
    });
  }

  openEditModal(user: any) {
    this.editUser = { ...user }; 
    this.showEditModal = true;
  }

  closeEditModal() {
    this.showEditModal = false;
    this.editUser = null;
  }

  updateUser() {
  
    this.http.delete(`http://localhost:3000/users/${this.editUser.id}`).subscribe({
      next: () => {
        this.http.post('http://localhost:3000/users', {
          username: this.editUser.username,
          password: this.editUser.password,
          role: this.editUser.role,
        }).subscribe({
          next: () => {
            this.loadUsers();
            this.closeEditModal();
          },
          error: (err) => {
            console.error('Failed to update user:', err);
          },
        });
      },
      error: (err) => {
        console.error('Failed to delete user during update:', err);
      },
    });
  }

  deleteUser(id: number) {
    this.http.delete(`http://localhost:3000/users/${id}`).subscribe({
      next: () => {
        this.loadUsers();
      },
      error: (err) => {
        console.error('Failed to delete user:', err);
      },
    });
  }

  logout() {
    localStorage.removeItem('role'); 
    this.router.navigate(['/login']); 
  }
}