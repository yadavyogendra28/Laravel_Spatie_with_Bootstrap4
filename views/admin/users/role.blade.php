@extends('layouts.masterLayout')

@section('title','Assign Role & Permissions ')


@section('content')

<div class="section-header">
    <h1>Assigned Roles & Permissions to User</h1>
</div>

<div class="container-fluid">
    <div class="flex p-2">
        <a href="{{ url('users') }}" class="btn btn-success">Users Index</a>
    </div>
    <div class="d-flex row p-3">
        <div class="col-6 fw-semibold">User Name : {{ $user->name }}</div>
        <div class="col-6 fw-semibold">User Email : {{ $user->email }}</div>
    </div>
    <div class="container-fluid bg-white p-4 row d-flex">


        {{-- <div class="col-6">
            <div class="mt-3 p-2 bg-light rounded">
                <h3 class=" fw-bold"> Assigned Roles</h3>
                <p class="text-dark">Click to unassign :</p>
                <div class="d-flex justify-content-start align-items-center mt-3">
                    @if ($user->roles)
                    @foreach ($user->roles as $user_role)
                    <form class="p-2 rounded-md" method="POST"
                        action="{{ route('admin.users.roles.remove', [$user->id, $user_role->id]) }}"
                        onsubmit="return confirm('Are you sure?');">
                        @csrf
                        @method('DELETE')
                        <button type="submit" class="btn btn-danger">{{ $user_role->name }}</button>
                    </form>
                    @endforeach
                    @endif
                </div>
                <div class="mt-4 shadow rounded p-3">
                    <form method="POST" action="{{ route('admin.users.roles', $user->id) }}">
                        @csrf
                        <div class="form-group">
                            <label for="role" class="text-dark fw-bold mb-2">Assign Role to User :</label>
                            <select id="role" name="role" class="form-control">
                                @foreach ($roles as $role)
                                <option value="{{ $role->name }}">{{ $role->name }}</option>
                                @endforeach
                            </select>
                        </div>
                        @error('role')
                        <span class="text-danger text-sm">{{ $message }}</span>
                        @enderror
                        <div class="mt-3">
                            <button type="submit" class="btn btn-success">Assign</button>
                        </div>
                    </form>
                </div>
            </div>
        </div> --}}




        <div class="col-12 col-md-6">
            <div class="shadow-sm rounded p-3">
                <h3 class="fw-bold">Assigned Roles</h3>
                <p>Toggle roles to assign or unassign:</p>

                <form id="roles-form" method="POST"
                    action="{{ route('admin.user.role.updateAll', ['user' => $user->id]) }}">
                    @csrf


                    <div class="form-check mb-3">
                        <input type="checkbox" class="form-check-input" id="selectAllCheckboxRole"
                            onclick="toggleAllRoles(this)">
                        <label class="form-check-label" for="selectAllCheckboxRole">Select All Roles</label>
                    </div>


                    <div class="container">
                        <div class="row">
                            @foreach ($roles as $role)
                            <div class="col-md-4 col-sm-6 col-12 mb-2">
                                <div class="form-check">
                                    <input class="form-check-input role-checkbox" type="checkbox" name="roles[]"
                                        value="{{ $role->name }}" id="role-{{ $role->id }}" {{ $user->hasrole($role) ?
                                    'checked' : '' }}>
                                    <label class="form-check-label" for="role-{{ $role->id }}">
                                        {{ $role->name }}
                                    </label>
                                </div>
                            </div>
                            @endforeach
                        </div>
                    </div>

                    <button type="submit" class="btn btn-success mt-3">Update Roles</button>
                </form>
            </div>
        </div>







        {{-- check all permsion option and check single permmsion form submit --}}
        <div class="col-12 col-md-6">
            <div class="shadow-sm rounded p-3">
                <h3 class="fw-bold">Assigned Specific Permissions</h3>

                <p class="">Toggle permissions to assign or unassign:</p>


                <form id="permissions-form" method="POST"
                    action="{{ route('admin.user.permissions.updateAll',['user'=> $user->id]) }}">
                    @csrf


                    <div class="form-check mb-3">
                        <input type="checkbox" class="form-check-input" id="select-all"
                            onclick="toggleAllPermissions(this)">
                        <label class="form-check-label" for="select-all">Select All Permissions</label>
                    </div>

                    <div class="container">
                        <div class="row">
                            @foreach ($permissions as $permission)
                            <div class="col-md-4 col-sm-6 col-12 mb-2">
                                <div class="form-check">
                                    <input class="form-check-input permission-checkbox" type="checkbox"
                                        name="permissions[]" value="{{ $permission->name }}"
                                        id="permission-{{ $permission->id }}" {{ $user->hasPermissionTo($permission) ?
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
    const checkboxes = document.querySelectorAll('.permission-checkbox');
    checkboxes.forEach((checkbox) => {
        checkbox.checked = selectAllCheckbox.checked;
    });
}
</script>

<script>
    // Toggle all role checkboxes based on the 'Select All' checkbox state
    function toggleAllRoles(selectAllCheckbox) {
        const checkboxes = document.querySelectorAll('.role-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.checked = selectAllCheckbox.checked;
        });
    }
</script>



@endsection