<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Illuminate\Support\Facades\Log;

class RoleController extends Controller
{
    public function index()
    {
        try {

            if (auth()->user()->hasRole('admin')) {
                $roles = Role::all();
                return view('admin.roles.index', compact('roles'));
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in index method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while loading roles.');
        }
    }

    public function create()
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                return view('admin.roles.create');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in create method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while loading the role creation form.');
        }
    }

    public function store(Request $request)
    {
        try {
            $validated = $request->validate(['name' => ['required', 'min:3']]);
            if (auth()->user()->hasRole('admin')) {
                Role::create($validated);
                return redirect('roles')->with('message', 'Role Created successfully.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in store method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while creating the role.');
        }
    }

    public function edit(Role $role)
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                $permissions = Permission::all();
                return view('admin.roles.edit', compact('role', 'permissions'));
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in edit method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while loading the edit form.');
        }
    }

    public function update(Request $request, Role $role)
    {
        try {
            $validated = $request->validate(['name' => ['required', 'min:3']]);
            if (auth()->user()->hasRole('admin')) {
                $role->update($validated);
                return redirect('roles')->with('message', 'Role Updated successfully.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in update method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while updating the role.');
        }
    }

    public function destroy(Role $role)
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                $role->delete();
                return back()->with('message', 'Role deleted.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in destroy method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while deleting the role.');
        }
    }

    public function updateAllPermissions(Request $request, Role $role)
    {
        try {
            if (auth()->user()->hasRole('admin')) {
                $role->syncPermissions($request->permissions ?? []);
                return back()->with('success', 'Permissions updated successfully.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in updateAllPermissions method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while updating permissions.');
        }
    }
}
