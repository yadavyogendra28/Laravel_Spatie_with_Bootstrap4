@extends('layouts.masterLayout')



@section('title','Create Permissions')

@section('content')


<div class="section-header">
    <h1> Create Permissions</h1>
</div>




<div class="py-12 container">
    <div class="max-w-7xl mx-auto px-4">
        <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg p-2">

            <div class="d-flex p-2">
                <a href="{{ url('permissions') }}" class="btn btn-primary">Permission Index</a>
            </div>

            <div class="d-flex flex-column">
                <div class="space-y-8 divide-y divide-gray-200 w-50 mt-10">
                    {{-- <form method="POST" action="{{ route('admin.permissions.store') }}">
                        @csrf
                        <div class="mb-3">
                            <label for="name" class="form-label">Permissions name</label>
                            <div class="mt-1">
                                <input type="text" id="name" name="name" class="form-control" />
                            </div>

                            <div class="form-group">
                                <label for="model">Select Model:</label>
                                <select name="model" id="model" class="form-control">
                                    @foreach ($models as $item)
                                    <option value="">Select Model </option>
                                    <option value="{{ $item }}"> {{ $item }}</option>
                                    @endforeach
                                </select>
                            </div>
                            @error('name')
                            <span class="text-danger">{{ $message }}</span>
                            @enderror
                        </div>
                        <div class="pt-5">
                            <button type="submit" class="btn btn-success">Create</button>
                        </div>
                    </form> --}}

                    <form method="POST" action="{{ route('admin.permissions.store') }}">
                        @csrf
                        <div class="mb-3">
                            <div class="form-group mt-3">
                                <label class="form-label">Select Actions</label>
                                <div class="mt-1">
                                    <div class="form-check">
                                        <input type="checkbox" id="select-all" class="form-check-input" />
                                        <label for="select-all" class="form-check-label">Select All</label>
                                    </div>

                                    <div class="form-check">
                                        <input type="checkbox" id="create" name="actions[]" value="create"
                                            class="form-check-input" />
                                        <label for="create" class="form-check-label">Create</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" id="read" name="actions[]" value="read"
                                            class="form-check-input" />
                                        <label for="read" class="form-check-label">Read</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" id="update" name="actions[]" value="update"
                                            class="form-check-input" />
                                        <label for="update" class="form-check-label">Update</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" id="delete" name="actions[]" value="delete"
                                            class="form-check-input" />
                                        <label for="delete" class="form-check-label">Delete</label>
                                    </div>
                                </div>
                            </div>

                            <div class="form-group mt-3">
                                <label for="model">Select Model:</label>
                                <select name="model" id="model" class="form-control" required>
                                    <option value="">Select Model</option>
                                    @foreach ($models as $item)
                                    <option value="{{ $item }}">{{ $item }}</option>
                                    @endforeach
                                </select>
                            </div>
                            @error('model')
                            <span class="text-danger">{{ $message }}</span>
                            @enderror
                        </div>
                        <div class="pt-5">
                            <button type="submit" class="btn btn-success">Create</button>
                        </div>
                    </form>

                </div>
            </div>
        </div>
    </div>
</div>


<script>
    document.getElementById('select-all').addEventListener('change', function() {
        const checkboxes = document.querySelectorAll('input[name="actions[]"]');
        checkboxes.forEach((checkbox) => {
            checkbox.checked = this.checked;
        });
    });
</script>
@endsection