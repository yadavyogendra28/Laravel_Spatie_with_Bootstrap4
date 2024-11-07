<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Illuminate\Support\Facades\Log;

class UserRoleController extends Controller
{
    public function index()
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                $users = User::with('roles')->get();
                return view('admin.users.index', compact('users'));
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in index method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while loading users.');
        }
    }

    public function show(User $user)
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                $roles = Role::all();
                $permissions = Permission::all();
                return view('admin.users.role', compact('user', 'roles', 'permissions'));
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in show method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while loading user roles.');
        }
    }

    public function assignRole(Request $request, User $user)
    {
        try {

            if (auth()->user()->hasRole('admin')) {

                if ($user->hasRole($request->role)) {
                    return back()->with('error', 'Role exists.');
                }

                $user->assignRole($request->role);
                return back()->with('success', 'Role assigned.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in assignRole method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while assigning role.');
        }
    }

    public function removeRole(User $user, Role $role)
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                if ($user->hasRole($role)) {
                    $user->removeRole($role);
                    return back()->with('success', 'Role removed.');
                }

                return back()->with('error', 'Role not exists.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in removeRole method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while removing role.');
        }
    }

    public function UserRoleUpdatedAll(Request $request, $user)
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                $user = User::findOrFail($user);
                $user->syncRoles($request->roles ?? []);
                return back()->with('success', 'Roles updated successfully.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in UserRoleUpdatedAll method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while updating roles.');
        }
    }

    public function destroy(User $user)
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                if ($user->hasRole('admin')) {
                    return back()->with('error', 'You are admin.');
                }
                $this->authorize('User-delete');
                $user->delete();
                return back()->with('success', 'User deleted.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in destroy method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while deleting user.');
        }
    }

    public function UserPermissionUpdateAll(Request $request, $user)
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                $user = User::findOrFail($user);
                $user->syncPermissions($request->permissions ?? []);
                return back()->with('success', 'Permissions updated successfully.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in UserPermissionUpdateAll method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while updating permissions.');
        }
    }
}
