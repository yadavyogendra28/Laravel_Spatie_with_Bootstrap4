<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;

class PermissionController extends Controller
{
    public function index()
    {
        try {
            if (auth()->user()->hasRole('admin')) {

                $permissions = Permission::all();
                return view('admin.permissions.index', compact('permissions'));
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in index method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while loading permissions.');
        }
    }

    public function create()
    {
        try {
            if (auth()->user()->hasRole('admin')) {

                $path = app_path('Models');
                $files = File::allFiles($path);
                $models = [];

                foreach ($files as $file) {
                    $namespace = 'App\Models';
                    $class = $namespace . '\\' . str_replace('.php', '', $file->getFilename());

                    if (class_exists($class) && is_subclass_of($class, 'Illuminate\Database\Eloquent\Model')) {
                        $models[] = class_basename($class);
                    }
                }

                return view('admin.permissions.create', compact('models'));
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in create method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while loading models.');
        }
    }

    public function store(Request $request)
    {
        try {
            $validatedData = $request->validate([
                'actions' => 'required|array',
                'actions.*' => 'in:create,read,update,delete',
                'model' => 'required|string',
            ]);
            if (auth()->user()->hasRole('admin')) {

                $model = $validatedData['model'];
                $actions = $validatedData['actions'];

                foreach ($actions as $action) {
                    $permissionName = "{$model}-{$action}";

                    if (Permission::where('name', $permissionName)->exists()) {
                        return redirect('permissions')->with('error', "Permission  '{$permissionName}' already exists.");
                    }

                    Permission::create(['name' => $permissionName]);
                }
                return redirect('permissions')->with('success', 'Permission created successfully.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in store method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while creating permission.');
        }
    }

    public function edit(Permission $permission)
    {
        try {
            if (auth()->user()->hasRole('admin')) {

                $roles = Role::all();
                $path = app_path('Models');
                $files = File::allFiles($path);
                $models = [];

                foreach ($files as $file) {
                    $namespace = 'App\Models';
                    $class = $namespace . '\\' . str_replace('.php', '', $file->getFilename());

                    if (class_exists($class) && is_subclass_of($class, 'Illuminate\Database\Eloquent\Model')) {
                        $models[] = class_basename($class);
                    }
                }

                $selectedActions = explode('-', $permission->name);
                $modelName = array_shift($selectedActions);
                $selectedActionsString = implode(', ', $selectedActions);

                return view('admin.permissions.edit', compact('permission', 'roles', 'selectedActionsString', 'models', 'modelName'));
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in edit method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while loading permission.');
        }
    }

    public function update(Request $request, Permission $permission)
    {
        try {
            $validatedData = $request->validate([
                'action' => 'required',
                'model' => 'required|string',
            ]);
            if (auth()->user()->hasRole('admin')) {

                $permission = Permission::findOrFail($permission->id);
                $model = $validatedData['model'];
                $action = $validatedData['action'];
                $newPermissionName = "{$model}-{$action}";

                if (Permission::where('name', $newPermissionName)->where('id', '!=', $permission->id)->exists()) {
                    return redirect()->back()->with('error', "Permission '{$newPermissionName}' already exists.");
                }

                $permission->name = $newPermissionName;
                $permission->save();

                return redirect()->route('admin.permissions.index')->with('success', 'Permission updated successfully.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in update method: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Something went wrong while updating permission.');
        }
    }

    public function destroy(Permission $permission)
    {
        try {
            if (auth()->user()->hasRole('admin')) {

                $permission->delete();
                return back()->with('message', 'Permission deleted.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in destroy method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while deleting permission.');
        }
    }

    public function assignRole(Request $request, Permission $permission)
    {
        try {
            if (auth()->user()->hasRole('admin')) {

                if ($permission->hasRole($request->role)) {
                    return back()->with('message', 'Role exists.');
                }

                $permission->assignRole($request->role);
                return back()->with('message', 'Role assigned.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in assignRole method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while assigning role.');
        }
    }

    public function removeRole(Permission $permission, Role $role)
    {
        try {
            if (auth()->user()->hasRole('admin')) {

                if ($permission->hasRole($role)) {
                    $permission->removeRole($role);
                    return back()->with('message', 'Role removed.');
                }

                return back()->with('message', 'Role not exists.');
            }
            return redirect()->back()->with('error', 'Unauthorized access: You do not have permission to view this page.');
        } catch (\Exception $e) {
            Log::error('Error in removeRole method: ' . $e->getMessage());
            return back()->with('error', 'Something went wrong while removing role.');
        }
    }
}
