@extends('layouts.masterLayout')

@section('title','Edit Role')

@section('content')

<div class="section-header mb-4">
    <h1>Edit Role & Permissions</h1>
</div>


<div class="container-fluid shadow-sm rounded p-4">

    <div class="d-flex mb-3">
        <a href="{{ url('roles') }}" class="btn btn-primary">Role Index</a>
    </div>

    <div class="row">
        <div class="col-12 col-md-4 mb-4">
            <h4>Update Role</h4>
            <form method="POST" action="{{ route('admin.roles.update', $role->id) }}">
                @csrf
                @method('PUT')
                <div class="mb-3">
                    <label for="name" class="form-label fw-semibold">Role name:</label>
                    <input type="text" id="name" name="name" value="{{ $role->name }}" class="form-control" />
                    @error('name')
                    <span class="text-danger">{{ $message }}</span>
                    @enderror
                </div>
                <button type="submit" class="btn btn-success">Update</button>
            </form>
        </div>




        {{-- check all permsion option and check single permmsion form submit --}}
        <div class="col-12 col-md-8">
            <div class="shadow-sm rounded p-3">
                <h4>Assign Permissions to This Role</h4>
                <p class="">Toggle permissions to assign or unassign:</p>


                <form id="permissions-form" method="POST"
                    action="{{ route('admin.roles.permissions.updateAll',['role'=> $role->id]) }}">
                    @csrf


                    <div class="form-check mb-3">
                        <input type="checkbox" class="form-check-input" id="select-all"
                            onclick="toggleAllPermissions(this)">
                        <label class="form-check-label" for="select-all">Select All Permissions</label>
                    </div>

                    <div class="container">
                        <div class="row">
                            @foreach ($permissions as $permission)
                            <div class="col-md-3 col-sm-6 col-12 mb-2">
                                <div class="form-check">
                                    <input class="form-check-input permission-checkbox" type="checkbox"
                                        name="permissions[]" value="{{ $permission->name }}"
                                        id="permission-{{ $permission->id }}" {{ $role->hasPermissionTo($permission) ?
                                    'checked' : '' }}>
                                    <label class="form-check-label" for="permission-{{ $permission->id }}">
                                        {{ $permission->name }}
                                    </label>
                                </div>
                            </div>
                            @endforeach
                        </div>
                    </div>

                    <button type="submit" class="btn btn-success mt-3">Update Permissions</button>
                </form>
            </div>
        </div>






    </div>
</div>

<script>
    // Toggle all permission checkboxes based on "Select All" checkbox state
        function toggleAllPermissions(selectAllCheckbox) {
            const permissionCheckboxes = document.querySelectorAll('.permission-checkbox');

            permissionCheckboxes.forEach(checkbox => {
                checkbox.checked = selectAllCheckbox.checked;
            });
        }
</script>





@endsection