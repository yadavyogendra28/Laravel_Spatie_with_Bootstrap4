@extends('layouts.masterLayout')

@section('title', 'Edit Permissions')

@section('content')

<div class="section-header">
    <h1>Edit Permissions</h1>
</div>

<div class="d-flex justify-content-between align-items-center mb-4">
    <a href="{{ url('permissions') }}" class="btn btn-primary">Permission Index</a>
</div>

<div class="container-fluid shadow rounded p-4">
    <div class="row">
        <div class="col-md-6 mb-4">
            <h2 class="h5 font-weight-bold">Update Permission</h2>

            <form method="POST" action="{{ route('admin.permissions.update', $permission) }}">
                @csrf
                @method('PUT')

                <div class="form-group mt-3">
                    <label for="action" class="form-label">Select Action</label>
                    <select name="action" class="form-control" required>
                        <option value="">Select Action</option>
                        <option value="create" {{ $selectedActionsString==='create' ? 'selected' : '' }}>Create</option>
                        <option value="read" {{ $selectedActionsString==='read' ? 'selected' : '' }}>Read</option>
                        <option value="update" {{ $selectedActionsString==='update' ? 'selected' : '' }}>Update</option>
                        <option value="delete" {{ $selectedActionsString==='delete' ? 'selected' : '' }}>Delete</option>
                    </select>
                </div>

                <div class="form-group mt-3">
                    <label for="model" class="form-label">Select Model</label>
                    <select name="model" id="model" class="form-control" required>
                        <option value="">Select Model</option>
                        @foreach ($models as $item)
                        <option value="{{ $item }}" {{ $modelName===$item ? 'selected' : '' }}>{{ $item }}</option>
                        @endforeach
                    </select>
                    @error('model')
                    <span class="text-danger">{{ $message }}</span>
                    @enderror
                </div>

                <div class="pt-4">
                    <button type="submit" class="btn btn-success">Update</button>
                </div>
            </form>
        </div>

        <div class="col-md-6">
            <h2 class="h5 font-weight-bold">Assign Permission to Roles</h2>
            <p class="font-weight-semibold">Click to remove:</p>

            <div class="d-flex flex-wrap mb-3">
                @if ($permission->roles)
                @foreach ($permission->roles as $permission_role)
                <form method="POST"
                    action="{{ route('admin.permissions.roles.remove', [$permission->id, $permission_role->id]) }}"
                    onsubmit="return confirm('Are you sure you want to remove?');" class="ml-1 mb-2">
                    @csrf
                    @method('DELETE')
                    <button type="submit" class="btn btn-danger text-white">{{ $permission_role->name }}</button>
                </form>
                @endforeach
                @endif
            </div>

            <form method="POST" action="{{ route('admin.permissions.roles', $permission->id) }}">
                @csrf
                <div class="form-group mb-3">
                    <label for="role" class="form-label">Roles</label>
                    <select id="role" name="role" class="form-control">
                        @foreach ($roles as $role)
                        <option value="{{ $role->name }}">{{ $role->name }}</option>
                        @endforeach
                    </select>
                    @error('role')
                    <div class="text-danger">{{ $message }}</div>
                    @enderror
                </div>


                <div>
                    <button type="submit" class="btn btn-success">Assign</button>
                </div>
            </form>
        </div>
    </div>
</div>

@endsection