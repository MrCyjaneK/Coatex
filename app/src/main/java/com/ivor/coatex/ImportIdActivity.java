package com.ivor.coatex;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.aditya.filebrowser.Constants;
import com.aditya.filebrowser.FileChooser;
import com.bumptech.glide.Glide;
import com.bumptech.glide.request.RequestOptions;
import com.google.android.material.textfield.TextInputEditText;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.ivor.coatex.crypto.AdvancedCrypto;
import com.ivor.coatex.db.Contact;
import com.ivor.coatex.db.Database;
import com.ivor.coatex.db.Message;
import com.ivor.coatex.utils.Settings;
import com.ivor.coatex.utils.Util;
import com.ivor.coatex.utils.ZipManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

import io.realm.Realm;

public class ImportIdActivity extends AppCompatActivity {

    private static final int PICK_FILE_REQUEST = 100;
    private static final String TAG = "ImportIdActivity";
    private TextView txtName;
    private TextView txtFilePath;
    private ImageView imvwImage;
    private ProgressBar progressBar;
    private String mImportFilePath;

    private View mImportDataView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_import_id);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        txtName = findViewById(R.id.txtName);
        txtFilePath = findViewById(R.id.txtFilePath);
        imvwImage = findViewById(R.id.imvwDp);
        progressBar = findViewById(R.id.progressBar);

        mImportDataView = findViewById(R.id.includedLayout);
        mImportDataView.setVisibility(View.GONE);

        findViewById(R.id.btnImport).setEnabled(false);
        findViewById(R.id.btnStart).setEnabled(false);

        ((RadioGroup) findViewById(R.id.radioGroup)).setOnCheckedChangeListener((radioGroup, i) -> {

            switch (i) {
                case R.id.rdbtnLightTheme:
//                    AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO);
                    Settings.putBoolean(getApplicationContext(), "use_dark_mode", false);
//                    recreate();
                    break;
                case R.id.rdbtnDarkTheme:
//                    AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES);
                    Settings.putBoolean(getApplicationContext(), "use_dark_mode", true);
//                    recreate();
                    break;
            }
        });
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
        }
        return super.onOptionsItemSelected(item);
    }

    public void onStartClicked(View v) {
        EditText txtName = findViewById(R.id.txtName);
        if (txtName.length() < 1) {
            txtName.setError("Please enter name");
            return;
        }
        Database.getInstance(this).setName(txtName.getText().toString().trim());
        Intent intent = new Intent(this, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);

        Settings.putBoolean(getApplicationContext(), "start_setup_completed", true);
    }

    public void onDpBoxClicked(View v) {

    }

    public void onFileSelectClicked(View view) {
        Intent fileChooserIntent = new Intent(getApplicationContext(), FileChooser.class);
        fileChooserIntent.putExtra(Constants.SELECTION_MODE, Constants.SELECTION_MODES.SINGLE_SELECTION.ordinal());
        fileChooserIntent.putExtra(Constants.INITIAL_DIRECTORY, Util.EXTERNAL_FOLDER.getAbsolutePath());
        fileChooserIntent.putExtra(Constants.ALLOWED_FILE_EXTENSIONS, "zip");
        startActivityForResult(fileChooserIntent, PICK_FILE_REQUEST);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != Activity.RESULT_OK) return;

        if (requestCode == PICK_FILE_REQUEST && data != null) {
            if (resultCode == RESULT_OK) {
                Uri file = data.getData();
                mImportFilePath = file.getPath();
                txtFilePath.setText(mImportFilePath);
                findViewById(R.id.btnImport).setEnabled(true);
            }
        }
    }

    public void onImportIdClicked(View view) {
        Log.d(TAG, "onImportIdClicked: trying to import " + mImportFilePath);
        showPasswordDialog();
    }

    private void showPasswordDialog() {
        final View view = getLayoutInflater().inflate(R.layout.dialog_one_password, null);
        final TextInputEditText txtPassword = view.findViewById(R.id.txtPassword);

        AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle(R.string.password_for_export_backup)
                .setView(view)
                .setPositiveButton(R.string.ok, (dialog, which) -> {

                })
                .setNegativeButton(R.string.cancel, (dialog, which) -> {
                }).create();

        alertDialog.setOnShowListener(dialogInterface -> {

            Button button = alertDialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE);
            button.setOnClickListener(view1 -> {

                String password = txtPassword.getText().toString().trim();
                if (password.length() < 8) {
                    txtPassword.setError("Password is less than 8 characters");
                    return;
                }

                new ImportID(password).execute(mImportFilePath);

                alertDialog.dismiss();
            });
        });

        alertDialog.show();
    }
    @SuppressWarnings("deprecation")
    private class ImportID extends AsyncTask<String, Void, Boolean> {

        private String mPassword;
        @SuppressWarnings("deprecation")
        public ImportID(String password) {
            mPassword = password;
        }

        @Override
        protected void onPreExecute() {
            super.onPreExecute();

            progressBar.setIndeterminate(true);
            findViewById(R.id.btnStart).setEnabled(false);
        }

        @Override
        protected Boolean doInBackground(String... strings) {

            ZipManager zipManager = new ZipManager(getApplicationContext());

            String inputFile = strings[0];
            String outPutFile = new File(getFilesDir(), "coatex_backup.zip").getAbsolutePath();

            try {
                AdvancedCrypto advancedCrypto = new AdvancedCrypto(mPassword);
                advancedCrypto.decryptFile(inputFile, outPutFile);
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }

            zipManager.unZip(getFilesDir().getAbsolutePath(), outPutFile);

            String settings = "settings.prop";
            String messages = "messages.json";
            String contacts = "contacts.json";

            Database database = Database.getInstance(getApplicationContext());

            Properties props = new Properties();
            try {
                props.load(new FileInputStream(new File(getFilesDir(), settings)));
                database.put("name", props.getProperty("name"));
                Settings.putBoolean(getApplicationContext(), "use_dark_mode", Boolean.parseBoolean(props.getProperty("use_dark_mode")));
            } catch (IOException e) {
                e.printStackTrace();
            }
            Realm realm = Realm.getDefaultInstance();
            realm.beginTransaction();
            Gson gson = new Gson();
            try {
                File contactsFile = new File(getFilesDir(), contacts);
                JsonReader jsonReader = new JsonReader(new FileReader(contactsFile));
                JsonElement jsonElement = JsonParser.parseReader(jsonReader);
                JsonArray asJsonArray = jsonElement.getAsJsonArray();
                for (JsonElement je : asJsonArray) {
                    Contact contact = gson.fromJson(je, Contact.class);
                    realm.copyToRealm(contact);
                }
                jsonReader.close();
                contactsFile.delete();

                File messagesFile = new File(getFilesDir(), messages);
                jsonReader = new JsonReader(new FileReader(messagesFile));
                jsonElement = JsonParser.parseReader(jsonReader);
                asJsonArray = jsonElement.getAsJsonArray();
                for (JsonElement je : asJsonArray) {
                    Message message = gson.fromJson(je, Message.class);
                    realm.copyToRealm(message);
                }
                jsonReader.close();
                messagesFile.delete();

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            realm.commitTransaction();
            realm.close();

            return true;
        }

        @Override
        protected void onPostExecute(Boolean aBoolean) {
            super.onPostExecute(aBoolean);
            progressBar.setIndeterminate(false);
            if (aBoolean) {

                mImportDataView.setVisibility(View.VISIBLE);

                findViewById(R.id.btnStart).setEnabled(true);
                txtName.setText(Database.getInstance(getApplicationContext()).get("name"));

                Uri resultUri = Uri.fromFile(new File(getFilesDir(), "dp.jpg"));

                Log.d(TAG, "onPostExecute: Loading DP: " + resultUri.getPath());

                boolean use_dark_theme = Settings.getPrefs(getApplicationContext()).getBoolean("use_dark_theme", false);
                if (use_dark_theme) {
                    ((RadioButton) findViewById(R.id.rdbtnDarkTheme)).setChecked(true);
                } else {
                    ((RadioButton) findViewById(R.id.rdbtnLightTheme)).setChecked(true);
                }

                Database.getInstance(getApplicationContext()).put("dp", resultUri.getPath());

//            Picasso.get().load(resultUri).transform(new CircleTransform())
//                    .into(imvwImage);
                Glide.with(ImportIdActivity.this)
                        .load(resultUri)
                        .apply(RequestOptions.circleCropTransform())
                        .into(imvwImage);
            } else {
                Toast.makeText(ImportIdActivity.this, "Unable to import, password might be incorrect", Toast.LENGTH_SHORT).show();
            }
        }
    }
}
